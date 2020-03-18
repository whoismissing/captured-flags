#!/usr/bin/python3

# Usage: gdb -q -x prog.py

import gdb
import struct

def stop_handler(event):
    #print(gdb.execute('x/32gx $rsp', to_string=True))
    return
        
def main():
    gdb.events.stop.connect(stop_handler)

    gdb.execute('file ./run')
    # break right at the debugger check
    gdb.execute("b * 0x00400ff9")

    # breakpoints at cmp instructions
    # 26 loops here
    #gdb.execute("b * 0x004010f0")

    # load ascii 1337key on the stack here
    #gdb.execute("b * 0x00401201")

    gdb.execute("b * 0x004012c7")
    # brekapoint at final comparison
    gdb.execute("b * 0x004012f5")
    #gdb.execute("b * 0x00401304")

    print(gdb.execute('r BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', to_string=True))
        
    rbp = gdb.execute("x/wx $rbp-0x120", to_string=True).split(":")[0]
    print(rbp)
    gdb.execute("set *" + rbp + "=0x6")
    #print(gdb.execute('c', to_string=True))

if __name__ == "__main__":
    main()
