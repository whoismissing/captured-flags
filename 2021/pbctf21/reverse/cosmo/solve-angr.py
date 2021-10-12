import sys

import angr
import claripy

use_entry=False
explore_to_end = True

project = angr.Project('hello.com')

flag_len = 38
#flag = claripy.BVS('flag0', flag_len*8)
flag = [ claripy.BVS('flag_' + str(idx), 8) for idx in range(flag_len) ]

loop_start = 0x004030a6
if use_entry:
    state = project.factory.entry_state(args=['./hello.com', flag])
else:
    state = project.factory.blank_state(addr=loop_start)

    flag_addr = 0x6969696969696969
    for idx in range(flag_len):
        state.memory.store(flag_addr + idx, flag[idx])

    envp_addr = 0x2222222222222222
    state.memory.store(envp_addr + 8, flag_addr)

    option_addr = 0x0040d039
    state.memory.store(option_addr, 0x00000000)

    state.regs.rip = loop_start
    state.regs.edx = 0x00000002
    state.regs.rbx = 0x0000000000000000
    state.regs.rdi = 0x0000000000000001
    state.regs.rax = 0x0000000000000001
    state.regs.r12 = envp_addr
    state.regs.rbp = 0x8888888888888888

simgr = project.factory.simgr(state)

correct = 0x004030d6
no = 0x00403115

solution = []

# pbctf{acKshuaLLy_p0rtable_3x3cutAbLe?}
if explore_to_end:
    correct = 0x004030d8 # end of loop
    simgr.explore(find=correct, avoid=no)
    if simgr.found:
        found_state = simgr.found[0]
        for idx in range(flag_len):
            found_state.add_constraints(flag[idx] >= 32)
            found_state.add_constraints(flag[idx] <= 126)
        for idx in range(flag_len):
            sol = found_state.solver.eval(flag[idx], cast_to=bytes)
            solution.append(sol)
    else:
        raise Exception(f'Could not find the solution for flag[{idx}]')
else:
    for idx in range(0, flag_len, 2):
        simgr.explore(find=correct, avoid=no)

        # pb
        if simgr.found:
            print("Found", len(simgr.found), "states")
            found_state = simgr.found[0]

            found_state.add_constraints(flag[idx] >= 32)
            found_state.add_constraints(flag[idx] <= 126)
            found_state.add_constraints(flag[idx + 1] >= 32)
            found_state.add_constraints(flag[idx + 1] <= 126)
            solution0 = found_state.solver.eval(flag[idx], cast_to=bytes)
            solution1 = found_state.solver.eval(flag[idx + 1], cast_to=bytes)

            print(solution0, solution1)
            solution.append(solution0)
            solution.append(solution1)

            simgr = project.factory.simgr(found_state)
        else:
            raise Exception(f'Could not find the solution for flag[{idx}]')

if solution:
    flag_str = ""
    for b in solution:
        flag_str += b.decode('utf-8')
    print(flag_str)
    assert len(flag_str) == flag_len

