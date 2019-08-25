# captured-flags

My solutions and notes for CTFs that I've played. This is a way for me to document my learning and techniques used.

This repository's organization is inspired from https://github.com/guyinatuxedo/ctf

## Binary Exploitation (pwn)

#### ROP Chain
+ x32: redpwnctf19/pwn/bronze_ropchain ROP to _dl_make_stack_executable then land shellcode on the stack
+ x32: redpwnctf19/pwn/zipline ROP to functions to prepare final function that will read the flag

#### Return 2 system
+ x32: redpwnctf19/pwn/hardmode Variant of ret2system, call system("sh #") with sh string and comment character

#### Format String
+ x32: redpwnctf19/pwn/rot26 Classic format string exploit, got overwrite of exit with function that calls system

## Reverse Engineering (RE)

#### Crackmes
+ x64: redpwnctf19/re/generic_crackmes Use final comparison that is the password / access code and reverse small transformations to user input.
+ x64: hackconctf19/re/babyrev Code before and after main xor "A" with sequence of bytes 9 at a time.
+ x64: codefestctf19/re/linux_re_1 Unpack with UPX and bypass ptrace debugger check, then xor sequence of bytes with key "1337key".

## Web

#### Code review
+ redpwnctf19/web/easy_cipher Find and crack the hash being compared to user input
