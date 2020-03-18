#!/usr/bin/python3

def get_12_least_bits(addr):
    x = int(addr, 16)
    y = '{0:08b}'.format(x)
    return int(y[20:], 2)

print(hex(get_12_least_bits("0xf7e05360")))
print(hex(get_12_least_bits("0xf7dbd540")))
print(hex(get_12_least_bits("0xf7dee670")))

# or just read the last 3 hex digits lol
