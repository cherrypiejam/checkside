import angr
import claripy

from models.base import Base
import utils, timing

"""

Timing Model: # instructions

Secrecy Model: the entire stdin stream

"""

def foo(state):
    state.block(addr=state.inspect.instruction, num_inst=1).pp()

DEBUG = False

class StdinInsts(Base):
    def __init__(self, path, env={}, **kwargs):
        self.path = path
        self.env = env

    def trace(self):

        p = angr.Project(self.path, auto_load_libs=False)
        s = p.factory.entry_state(env=self.env)

        if DEBUG:
            s.inspect.b('instruction', when=angr.BP_BEFORE, action=foo)

        sm = p.factory.simulation_manager(s)
        sm.run()

        if DEBUG:
            print(sm.deadended)
            print(sm.active)
            print(sm.errored[0])

        return {
            d : [
                d.block(a)
                for a in d.history.bbl_addrs
            ]
            for d in sm.deadended
        }


    def filter(self, traces):
        return traces


    def analyse(self, traces):

        paired = [
            (p[0], p[1]) if len(traces[p[0]]) < len(traces[p[1]]) else (p[1], p[0])
            for p in utils.combinations(list(traces.keys()), 2)
            if timing.calc_trace_instructions(traces[p[0]])
                != timing.calc_trace_instructions(traces[p[1]])
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
                    #  print(str(traces[paired[0][0]][i].disassembly))
                    #  print('second ++++++++++++++++')
                    #  print(str(traces[paired[0][1]][i].disassembly))
                #  else:
                    #  print('first')
                    #  print('-----------------------------')
                    #  print('second ++++++++++++++++')
                    #  print(str(traces[paired[0][1]][i].disassembly))

            #  print([str(b.disassembly) for b in traces[paired[0][0]]])
            #  print(])


        filtered = [
            (fst, snd)
            for fst, snd in paired
            if utils.is_unsat(
                utils.stdin_bitvectors(fst)[0],
                utils.constraints(fst, utils.stdin_variables(fst)),
                utils.constraints(snd, utils.stdin_variables(snd)),
            )
        ]


        results = [
            ({ 'inputs': fst.posix.dumps(0), '# instructions': timing.calc_trace_instructions(traces[fst])}
            ,{ 'inputs': snd.posix.dumps(0), '# instructions': timing.calc_trace_instructions(traces[snd])})
            for fst, snd in filtered
        ]

        return results
