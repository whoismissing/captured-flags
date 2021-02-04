aa
s 0x00
aei
aeim
aeip

aer esi=0x26
aer edi=0x420420

# create a macro 
#(ptrace_hook; ?e call ptrace; aepc=[esp]; ae 1,rax,=)

# create an alias
"$step_h=#!pipe python3 hooks.py"

# set the macro to the alias
(handle; $step_h)

# pin the macro
aep .(handle) @ 0x132 # cmp edx, eax
aep .(handle) @ 0x134 # jz loc_13D

