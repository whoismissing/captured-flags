#!/usr/bin/env python
import sys
import r2pipe

def get_jmp_addr(pipe, pc):
    cmd_response = pipe.cmd("pie 1 @ %s" % pc).rstrip()
    print(cmd_response)
    esil_inputs = cmd_response.split(",")
    jmp_index = esil_inputs.index("rip") - 1
    jmp_addr = esil_inputs[jmp_index]
    return jmp_addr

def cmp_hook(pipe, pc):
    print("cmp hook hit")
    rdx = pipe.cmd("ar rdx")
    print(f"rdx = {rdx}")
    with open("flag.txt", "a+") as fd:
        char = chr(int(rdx, 16))
        fd.write(char)

def jz_hook(pipe, pc):
    print("taking jz hook")
    jmp_addr = get_jmp_addr(pipe, pc)
    pipe.cmd("aer rip = %s" % jmp_addr)
    # 0x13D

class StepHandler:

    def __init__(self):
        self.pipe = r2pipe.open()
        self.hooks = {
            0x00132: cmp_hook,
            0x00134: jz_hook,
        }

    def handle_hook(self, pc):
        '''
        Check if current program counter has a hook, then run the hook
        '''
        if pc in self.hooks:
            self.hooks[pc](self.pipe, pc)

    def handle_step(self):
        '''
        On each step, grab the current program counter and print it along
        with the current instruction
        '''
        cmd_response = self.pipe.cmd("dr?PC").rstrip()
        pc = int(cmd_response, 16)
        current_instruction = self.pipe.cmd("pd 1 @ %s" % pc)
        print(hex(pc), current_instruction)

        self.handle_hook(pc)

def main():
    handler = StepHandler()
    handler.handle_step()
    sys.exit(0)

if __name__ == "__main__":
    main()

