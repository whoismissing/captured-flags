# captured-flags

My solutions and notes for CTFs that I've played. This is a way for me to document my learning and techniques used. For all of the successful solves here, there are many more challenges for which I failed and learned from.

This repository's organization is inspired from https://github.com/guyinatuxedo/ctf

## Binary Exploitation (pwn)

#### ROP Chain
+ x32: [2019/redpwnctf19/pwn/bronze_ropchain](https://github.com/whoismissing/captured-flags/blob/master/2019/redpwnctf19/pwn/bronze_ropchain/bronze_ropchain_gdb.py) ROP to _dl_make_stack_executable then land shellcode on the stack
+ x32: [2019/redpwnctf19/pwn/zipline](https://github.com/whoismissing/captured-flags/blob/master/2019/redpwnctf19/pwn/zipline/zipline_exploit.py) ROP to functions to prepare final function that will read the flag
+ x64: [2019/csawquals19/pwn/baby_boi](https://github.com/whoismissing/captured-flags/blob/master/2019/csawquals19/pwn/baby_boi/baby_boi_solution.py) Given a leaked printf libc address, buffer overflow, then ROP to one_gadget

#### Return 2 system
+ x32: [2019/redpwnctf19/pwn/hardmode](https://github.com/whoismissing/captured-flags/blob/master/2019/redpwnctf19/pwn/hardmode/notes.txt) Variant of ret2system, call system("sh #") with sh string and comment character
+ x32: [2019/tuctf19/pwn/thefirst](https://github.com/whoismissing/captured-flags/blob/master/2019/tuctf19/pwn/thefirst/thefirst.py) Classic return to calling system("/bin/cat ./flag.txt")
+ x32: [2019/tuctf19/pwn/ctftp](https://github.com/whoismissing/captured-flags/blob/master/2019/tuctf19/pwn/ctftp/ctftp.py) Store "/bin/sh" string in global data as a username, then ret2system

#### Sigreturn Oriented Programming (SROP)
+ x64: [2019/csawquals19/pwn/small_boi](https://github.com/whoismissing/captured-flags/blob/master/2019/csawquals19/pwn/small_boi/small_boi_exploit.py) Static binary containing sigreturn gadget, buffer overflow to sigreturn and load necessary registers to make the syscall execve("/bin/sh", 0, 0)

#### Format String
+ x32: [2019/redpwnctf19/pwn/rot26](https://github.com/whoismissing/captured-flags/blob/master/2019/redpwnctf19/pwn/rot26/notes.txt) Classic format string exploit, got overwrite of exit with function that calls system
+ x32: [2019/tuctf19/pwn/vulnmath](https://github.com/whoismissing/captured-flags/blob/master/2019/tuctf19/pwn/vulnmath/vulnmath.py) Format string exploit, user input can be passed 5 times, so leak puts got_plt then overwrite free got_plt with system libc address with the remaining loops in four writes
+ x32: [2019/tuctf19/pwn/printfun](https://github.com/whoismissing/captured-flags/blob/master/2019/tuctf19/pwn/printfun/printfun.py) Format string exploit, overwrite the same value to two buffers so strcmp(buf1, buf2) will return true

#### Stack Buffer Overflow
+ x32: [2019/tuctf19/pwn/3step](https://github.com/whoismissing/captured-flags/blob/master/2019/tuctf19/pwn/3step/3step.py) Stack buffer overflow to execute shellcode among two buffers jumping from stack to heap
+ x32: [2019/tuctf19/pwn/pancakes](https://github.com/whoismissing/captured-flags/blob/master/2019/tuctf19/pwn/pancakes/pancakes.py) Stack buffer overflow to call puts() to leak a password in data section
+ x32: [2019/tuctf19/pwn/leakalicious](https://github.com/whoismissing/captured-flags/blob/master/2019/tuctf19/pwn/leakalicious/leakalicious_final.py) Leak puts libc address, then use libc.blukat.me libc database to identify libc version. Stack buffer overflow and ROP to one_gadget

## Reverse Engineering (RE)

#### Crackmes
+ x64: [2019/redpwnctf19/re/generic_crackmes](https://github.com/whoismissing/captured-flags/blob/master/2019/redpwnctf19/re/generic_crackmes/notes.txt) Use final comparison that is the password / access code and reverse small transformations to user input.
+ x64: [2019/hackconctf19/re/babyrev](https://github.com/whoismissing/captured-flags/blob/master/2019/hackconctf19/re/babyrev.md) Code before and after main xor "A" with sequence of bytes 9 at a time.
+ x64: [2019/codefestctf19/re/linux_re_1](https://github.com/whoismissing/captured-flags/blob/master/2019/codefestctf19/re/linux_re_1/linux_re_1.md) Unpack with UPX and bypass ptrace debugger check, then xor sequence of bytes with key "1337key".

## Web

#### Code review
+ [2019/redpwnctf19/web/easy_cipher](https://github.com/whoismissing/captured-flags/blob/master/2019/redpwnctf19/web/easy_cipher/notes.txt) Find and crack the hash being compared to user input
