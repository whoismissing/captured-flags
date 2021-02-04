#!/usr/bin/env python
from pwn import *

context.update(arch='amd64')
context.terminal = ["tmux", "splitw", "-h"]
exe = ['/usr/local/bin/r2', '-i', 'init_emu.r2', './check_pass.bin']

def start(argv=[], *a, **kw):
    return process(exe + argv, *a, **kw)

gdbscript = '''
pie b * 0x12A7
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()

prompt = b"[0x00000000]>"
io.recvuntil(prompt)

flag_len = 0x26
while True:
    io.sendline(b"aesu 0x132")
    io.recvuntil(b"[0x00000114]>")

io.interactive()

