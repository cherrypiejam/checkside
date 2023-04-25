import angr
import csv

from models.base import Base
import utils, timing

"""

Timing Model: # core clock cycles

Secrecy Model: the entire stdin stream

"""


class StdinCycles(Base):

    def __init__(self, path, inst_table_path, env={}):
        self.path = path
        self.env = env
        with open(inst_table_path, 'r') as f:
            self.inst_table = list(csv.DictReader(f))

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


    def calc_cycles(self, trace):
        cycles, fails = timing.calc_trace_cycles(trace, self.inst_table)
        return sum(cycles) + len(fails)

    def analyse(self, traces):
        paired = [
            (p[0], p[1]) if len(traces[p[0]]) < len(traces[p[1]]) else (p[1], p[0])
            for p in utils.combinations(list(traces.keys()), 2)
            if self.calc_cycles(traces[p[0]])
                != self.calc_cycles(traces[p[1]])
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
            ((fst.posix.dumps(0), self.calc_cycles(traces[fst]))
            ,(snd.posix.dumps(0), self.calc_cycles(traces[snd])))
            for fst, snd in filtered
        ]

        for r in results:
            print(r)