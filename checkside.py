import angr
import claripy
import utils

#  def track_instructions(state):
    #  addr = state.inspect.instruction

#  def simple_tracer(path, env={}):
    #  p = angr.Project(path, auto_load_libs=False)

    #  s = p.factory.entry_state(env=env)
    #  sm = p.factory.simulation_manager(s)
    #  sm.run()

    #  traces = {}
    #  for d in sm.deadended:
        #  traces[d] = []
        #  for a in d.history.bbl_addrs:
            #  traces[d].append(d.block(a, num_inst=1))

    #  return traces


#  # traces { state: block }
#  # suppose stdin is sec
#  def simple_filter(traces, env={}):
    #  # TODO filter irrelavent traces based on secrecy model
    #  return traces

#  def analyzer(traces):
    #  # TODO 1) whether there's a leak or no - timing variance
    #  # 2) if so, back trace to which part? stdin[a:b] or env

    #  #  print(traces.items())
    #  #  print([ len(l) for l in traces.values() ])
    #  #  for p in utils.combinations(list(traces.keys()), 2):
        #  #  print(traces[p[0]])

    #  paired = [
        #  (p[0], p[1]) if len(traces[p[0]]) < len(traces[p[1]]) else (p[1], p[0])
        #  for p in utils.combinations(list(traces.keys()), 2)
        #  if len(traces[p[0]]) != len(traces[p[1]])
    #  ]

    #  print([(len(traces[p0]), len(traces[p1])) for p0, p1 in paired])
    #  for p0, p1 in paired:
        #  print(len(traces[p0]), stdin_dump(p0))
        #  print(len(traces[p1]), stdin_dump(p1))
        #  print('------')

    #  # TODO 2) backtrace to which part




#  # traces { state: block }
#  # suppose stdin is sec
#  def simple_filter_2(traces, env={}):
    #  filtered = {}
    #  for s, b in traces.items():
        #  print(stdin_dump(s))
        #  print(s.posix.stdin.content)
        #  print(stdin_constraints(s))
        #  constraints = s.solver.constraints
        #  #  for c in constraints:
            #  #  sc = claripy.simplify(c)
            #  #  print(c)
            #  #  print(type(sc.to_claripy()))
            #  #  print(type(c))
        #  #  print(s.posix.environ)
        #  #  print(s.solver.eval(s.posix.environ, cast_to=bytes))
        #  print("----", type(s.solver.constraints))
        #  print("----", s.solver.constraints)
        #  for k in env:
            #  bs2 = s.solver.eval(env[k], cast_to=bytes)
            #  #  print("-------", k, "------", bs2)
        #  #  input_data = s.posix.stdin.load(0, s.posix.stdin.size)
        #  #  bs = s.solver.eval(input_data[0], cast_to=bytes)
        #  #  print(s.solver.eval(symbolic_var, cast_to=bytes))
        #  #  print('---')
    #  return filtered

#  def stdin_dump(state):
    #  return state.posix.dumps(0)

#  #  def stdin_dump_list(state):
    #  #  lengths = [state.solver.eval(x[1]) for x in state.posix.stdin.content]
    #  #  sizes = [x[0].size() for x in state.posix.stdin.content]
    #  #  return [
        #  #  b"" if i == 0 else state.solver.eval(x[0][: size - i * state.arch.byte_width], cast_to=bytes)
        #  #  for i, size, x in zip(lengths, sizes, state.posix.stdin.content)
    #  #  ]

#  def stdin_constraints(state):
    #  lengths = [state.solver.eval(x[1]) for x in state.posix.stdin.content]
    #  sizes = [x[0].size() for x in state.posix.stdin.content]
    #  return [
        #  x[0][: size - i * state.arch.byte_width]
        #  for i, size, x in zip(lengths, sizes, state.posix.stdin.content)
    #  ]

#  def env_dump(state, env={}):
    #  return {k: state.solver.eval(v, cast_to=bytes) for k, v in env.items()}


BSIZE = 8
DEFAULT_ENV = {
    "PATH"  : claripy.BVS('path_val', 8 * BSIZE),
    "AUTH"  : claripy.BVS('auth_val', 8 * BSIZE),
    "TOKEN" : claripy.BVS('token_val', 8 * BSIZE),
}

from base_model import BaseModel
from default_model import DefaultModel

def checkside(model: BaseModel, path, env={}):
    trace   = model.trace
    filter  = model.filter
    analyse = model.analyse
    return analyse(trace(filter(path, env), env), env)

if __name__ == '__main__':
    path = 'examples/branches'
    my_env = dict (
        DEFAULT_ENV, **{
        "BRANCHES": claripy.BVS('br_val', 8 * BSIZE),
    })

    result = checkside(DefaultModel(), path, my_env)
    print(result)

