import angr
import csv
import utils
import timing
from base_model import BaseModel


"""Default

Timing Model: # core clock cycles

Secrecy Model: the entire stdin stream

"""

def parse_immediate_data(s: str) -> str | None:
    if s.startswith('0x'):
        try:
            int(s, 16)
        except:
            return None
        return 'i'
    elif s.isdigit():
        return 'i'
    return None

def parse_register(s: str) -> str | None:
    r64 = [ 'rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi' ]
    r32 = [ r.replace('r', 'e', 1) for r in r64 ]
    r16 = [ r[1:] for r in r64 ]
    r8  = [ r.replace('x', '', 1) + s for r in r16 for s in [ 'l', 'h' ][:r.count('x')+1] ]

    s = s.lower()
    #  if s == 'rsp':
        #  return 'stack pointer'
    if s in r64:
        return 'r64'
    elif s in r32:
        return 'r32'
    elif s in r16:
        return 'r16'
    elif s in r8:
        if len(s) == 2:
            return 'r8' + s[-1]
        return 'r8'
    return None


def parse_memory_oprand(s: str) -> str | None:
    s = s.lower()
    if 'byte ptr' in s:
        return 'm8'
    elif 'word ptr' in s:
        return 'm16'
    elif 'dword ptr' in s:
        return 'm32'
    elif 'qword ptr' in s:
        return 'm64'
    return None

def parse_oprand(s: str) -> str | None:
    s = s.lower()
    ret = parse_immediate_data(s)
    if not ret:
        ret = parse_register(s)
    if not ret:
        ret = parse_memory_oprand(s)
    return ret


class Model(BaseModel):

    def __init__(self, path, inst_table_path, env={}):
        self.path = path
        self.env = env
        with open(inst_table_path, 'r') as f:
            self.inst_table = csv.DictReader(f)
            #  for r in reader:
                #  print(dir(reader))
                #  break

    def trace(self):

        p = angr.Project(self.path, auto_load_libs=False)
        s = p.factory.entry_state(env=self.env)
        sm = p.factory.simulation_manager(s)
        sm.run()

        return {
            d : [
                d.block(a)
                for a in d.history.bbl_addrs
            ]
            for d in sm.deadended
        }


    def filter(self, traces):
        return traces


    @staticmethod
    def calc_inst_latency(inst):
        opcode = inst[0]
        oprands = inst[1].replace(', ', ',').split(',')


        print(inst)
        print(opcode)
        print(oprands)

        print([ parse_oprand(o) for o in oprands ])

        print()


    @staticmethod
    def calc_latency(trace):

        # parse trace to a list of instructions
        insts = [
            inst.split('\t')[1:]
            for b in trace
            for inst in str(b.disassembly).split('\n')
        ]

        for  i in insts:
            Model.calc_inst_latency(i)

        #  print(Model.calc_inst_latency(insts[0]))

    def analyse(self, traces):

        Model.calc_latency(traces[list(traces.keys())[0]])


        return None

        paired = [
            (p[0], p[1]) if len(traces[p[0]]) < len(traces[p[1]]) else (p[1], p[0])
            for p in utils.combinations(list(traces.keys()), 2)
            if timing.num_instructions(traces[p[0]])
                != timing.num_instructions(traces[p[1]])
        ]


        #  results = [
            #  ((fst.posix.dumps(0), len(traces[fst])), (snd.posix.dumps(0), len(traces[snd])))
            #  for fst, snd in paired
        #  ]
        #  for r in results:
            #  print(r)
            #  for i, b in enumerate(traces[paired[0][1]]):
                #  if i < len(traces[paired[0][0]]):
                    #  print('first')
                    #  print(traces[paired[0][0]][i].disassembly)
                    #  print('second ++++++++++++++++')
                    #  print(traces[paired[0][1]][i].disassembly)
                #  else:
                    #  pass
                    #  #  print('first')
                    #  #  print('-----------------------------')
                    #  #  print('second ++++++++++++++++')
                    #  #  print(str(traces[paired[0][1]][i].disassembly))

            #  #  print([str(b.disassembly) for b in traces[paired[0][0]]])
            #  #  print(])


        #  filtered = [
            #  (fst, snd)
            #  for fst, snd in paired
            #  if utils.is_unsat(
                #  utils.stdin_bitvectors(fst)[0],
                #  utils.constraints(fst, utils.stdin_variables(fst)),
                #  utils.constraints(snd, utils.stdin_variables(snd)),
            #  )
        #  ]


        #  results = [
            #  ((fst.posix.dumps(0), timing.num_instructions(traces[fst]))
            #  ,(snd.posix.dumps(0), timing.num_instructions(traces[snd])))
            #  for fst, snd in filtered
        #  ]

        #  # TODO 2) backtrace to which part

        #  for r in results:
            #  print(r)

