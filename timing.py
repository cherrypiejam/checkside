
##########################
# Number of Instructions #
##########################

# a trace is a list of basic blocks
def calc_trace_instructions(trace):
    return sum([
        b.instructions
        for b in trace
    ])


###############################
# Number of Core Clock Cycles #
###############################

def parse_immediate_data(s: str) -> list[str]:
    if s.startswith('0x'):
        try:
            int(s, 16)
        except:
            return []
        return ['i']
    elif s.isdigit():
        return ['i']
    return []

def parse_register(s: str) -> list[str]:
    r64 = [ 'rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi' ]
    r32 = [ r.replace('r', 'e', 1) for r in r64 ]
    r16 = [ r[1:] for r in r64 ]
    r8  = [ r.replace('x', '', 1) + s for r in r16 for s in [ 'l', 'h' ][:r.count('x')+1] ]

    s = s.lower()
    #  if s == 'rsp':
        #  return 'stack pointer'
    r = ['r']
    if s in r64:
        return ['r64', *r]
    elif s in r32:
        return ['r32', *r]
    elif s in r16:
        return ['r16', *r]
    elif s in r8:
        if len(s) == 2:
            return ['r8' + s[-1], *r]
        return ['r8', *r]
    return []


def parse_memory_operand(s: str) -> list[str]:
    s = s.lower()
    m = ['m']
    if 'byte ptr' in s:
        return ['m8', *m]
    elif 'word ptr' in s:
        return ['m16', *m]
    elif 'dword ptr' in s:
        return ['m32', *m]
    elif 'qword ptr' in s:
        return ['m64', *m]
    return []

def parse_operand(s: str) -> list[str]:
    s = s.lower()
    ret = parse_immediate_data(s)
    if not ret:
        ret = parse_register(s)
    if not ret:
        ret = parse_memory_operand(s)
    return ret

def calc_inst_cycles(inst, inst_table):
    opcode = inst[0]
    operands = [ parse_operand(o) for o in inst[1].replace(', ', ',').split(',') ]

    latency = None

    for r in inst_table:
        if opcode not in r['Instruction'].lower().split():
            continue

        inst_operands = [
            [ e for e in o.replace(' / ', '/').split('/') ]
            for o in r['Operands'].lower().replace(' , ', ',').split(',')
        ]
        for o in inst_operands:
            for i, e in enumerate(o):
                if not e.isdigit():
                    continue
                o[i] = o[i-1][0] + e


        if len(operands) != len(inst_operands):
            continue

        if not all([
            any([o in instos for o in os])
            for os, instos in zip(operands, inst_operands)
        ]):
            continue

        if r['Latency']:
            latency = int(r['Latency'].replace('~', '').split('-')[-1])
            break

    return latency


def calc_trace_cycles(trace, inst_table):
    # parse trace to a list of instructions
    # such that inst = ['opcode', 'oprand[,oprand]']
    insts = [
        inst.split('\t')[1:]
        for b in trace
        for inst in str(b.disassembly).split('\n')
    ]

    latencies = []
    fails = []
    for i in insts:
        latency = calc_inst_cycles(i, inst_table)
        if latency is None:
            fails.append(i)
        else:
            latencies.append(latency)

    return (latencies, fails)
