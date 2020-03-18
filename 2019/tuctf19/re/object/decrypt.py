#!/usr/bin/python3

def bit_not(n, numbits=8):
    return (1 << numbits) - 1 - n

def decrypt(bite):
    b = bite ^ 0xaa
    not_b = bit_not(b)
    sr = not_b >> 1
    print(chr(sr), end="")

with open("password.bin", "rb") as pass_file:
    encrypted_pass = pass_file.read()
    print(encrypted_pass)

    for c in encrypted_pass:
        decrypt(c)
