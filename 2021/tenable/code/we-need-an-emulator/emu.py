DRX = b""
#TRX = b"UL\x03d\x1c'G\x0b'l0kmm_" # test string
TRX = b"GED\x03hG\x15&Ka =;\x0c\x1a31o*5M"

def mov(op1, op2):
    global DRX
    global TRX
    print("MOV", op1, op2)
    if "DRX" in op1:
        op1 = DRX
        dst = "DRX"
    elif "TRX" in op1:
        op1 = TRX
        dst = "TRX"

    if "DRX" in op2:
        op2 = DRX
    elif "TRX" in op2:
        op2 = TRX

    if isinstance(op2, str):
        op2 = op2.encode('utf-8')

    dst_val = op2

    if "DRX" in dst:
        DRX = dst_val
    if "TRX" in dst:
        TRX = dst_val
    print(dst, dst_val)
    return dst_val

def xor(op1, op2):
    global DRX
    global TRX
    print("XOR", op1, op2)
    # op2 ^ op1
    # stored in op1
    dst = None

    if "DRX" in op1:
        op1 = DRX
        dst = "DRX"
    elif "TRX" in op1:
        op1 = TRX
        dst = "TRX"

    if "DRX" in op2:
        op2 = DRX
    elif "TRX" in op2:
        op2 = TRX

    if isinstance(op1, str):
        op1 = op1.encode('utf-8')
    if isinstance(op2, str):
        op2 = op2.encode('utf-8')

    op1_len = len(op1)
    op2_len = len(op2)
    if op1_len > op2_len:
        op2 = op2.ljust(op1_len, b"\x00")
    else:
        op1 = op1.ljust(op2_len, b"\x00")

    idx = 0
    dst_val = b""
    for b in op2:
        b = b ^ op1[idx]
        idx += 1
        dst_val += b.to_bytes(1, byteorder='big')
    if "DRX" in dst:
        DRX = dst_val
    if "TRX" in dst:
        TRX = dst_val
    print(dst, dst_val)
    return dst_val

def reverse(op1):
    global DRX
    global TRX
    print("REVERSE", op1)
    if "DRX" in op1:
        op1 = DRX
        dst = "DRX"
    elif "TRX" in op1:
        op1 = TRX
        dst = "TRX"

    if isinstance(op1, str):
        op1 = op1.encode('utf-8')

    dst_val = op1[::-1]
    if "DRX" in dst:
        DRX = dst_val
    if "TRX" in dst:
        TRX = dst_val
    print(dst, dst_val)
    return dst_val

def decode(instruction):
    tokens = instruction.split(" ")
    num_tokens = len(tokens)

    operation = tokens[0]
    dst = tokens[1].replace('"', "")
    if num_tokens == 3:
        src = tokens[2].replace('"', "")

    if operation == "MOV":
        mov(dst, src)
    elif operation == "XOR":
        xor(dst, src)
    elif operation == "REVERSE":
        reverse(dst)

def emulate(filename):
    code = ""
    with open(filename, "r") as fd:
        code = fd.read()

    for instruction in code.split("\n"):
        print(instruction)
        decode(instruction)

emulate("Crypto.asm")

