import angr
import claripy
import utils
import timing
from base_model import BaseModel


"""Default

Timing Model: # instructions

Secrecy Model: the entire stdin stream

"""

class DefaultModel(BaseModel):
    def __init__(self, path, env={}):
        self.path = path
        self.env = env

    def trace(self):

        p = angr.Project(self.path, auto_load_libs=False)
        s = p.factory.entry_state(env=self.env)
        sm = p.factory.simulation_manager(s)
        sm.run()

        #  for d in sm.deadended:
            #  for a in d.history.bbl_addrs:
                #  b = d.block(a)
                #  print(b.instructions)


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
            ((fst.posix.dumps(0), timing.num_instructions(traces[fst]))
            ,(snd.posix.dumps(0), timing.num_instructions(traces[snd])))
            for fst, snd in filtered
        ]

        # TODO 2) backtrace to which part

        for r in results:
            print(r)

        #  for p0, p1 in paired:

            #  p0_cs = utils.constraints(p0, utils.stdin_variables(p0))
            #  p1_cs = utils.constraints(p1, utils.stdin_variables(p1))


            #  bv = utils.stdin_bitvectors(p0)[0]
            #  print(p0.posix.dumps(0), p1.posix.dumps(0))
            #  print(utils.is_unsat(bv, p0_cs, p1_cs))

            #  remaining = utils.stdin_variables(p0)
            #  visited = set()
            #  p0_constraints = set()


            #  print(p0.solver.constraints)
            #  print()
            #  print('remaining', remaining)


            #  while remaining:
                #  var = remaining.pop()
                #  visited.add(var)
                #  print(var)
                #  for c in p0.solver.constraints:
                    #  if var in c.variables:
                        #  p0_constraints.add(c)
                        #  remaining = [ *remaining, *[ v for v in c.variables if v not in visited ] ]

            #  print(p0.solver.constraints)
            #  print(p0_constraints)
            #  print('visited', visited)

            #  s = claripy.Solver()
            #  a = claripy.BVS("sym_val", 8)
            #  cs = [a >= 2, a < 3]
            #  cs2 = claripy.Not(claripy.And(cs[0], *cs[1:]))
            #  s.add(cs)
            #  s.add(cs2)

            #  print(utils.is_unsat(a, cs))

            #  s.add([t])
            #  s.add(claripy.Not([a != 0]))

            #  bv = utils.stdin_bitvectors(p0)[0]
            #  print(utils.is_unsat(bv, p1_cs, claripy.Not(claripy.And(p1_cs[0], *p1_cs[1:]))))


            #  s.eval(a, 1)

            #  s.add(p0_cs)
            #  s.add(p1_cs)
            #  s.add(not p1_cs)
            #  print(s.eval(utils.stdin_bitvectors(p0)[0], 1))

                #  p0_constraints.update({ c for c in p0.solver.constraints if var in c.variables })
                #  for c in p0.solver.constraints:



            #  stdvar= utils.stdin_constraints(p0)
            #  print(utils.stdin_constraints(p0))
            #  cs = p0.solver.constraints
            #  print(cs[0])
            #  print(cs[0].variables)
            #  print(dir(cs[0].variables))
            #  print(utils.stdin_constraints(p1))

            #  break

        #  return paired

        #  filtered = [
            #  for p0, p1 in paired
            #  if p0, p1
        #  ]


        #  print([(len(traces[p0]), len(traces[p1])) for p0, p1 in paired])
        #  for p0, p1 in paired:
            #  print(len(traces[p0]), stdin_dump(p0))
            #  print(len(traces[p1]), stdin_dump(p1))
            #  print('------')

