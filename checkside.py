import angr
import claripy

def track_instructions(state):
    addr = state.inspect.instruction

def simple_tracer(path, env={}):
    p = angr.Project(path, auto_load_libs=False)

    s = p.factory.entry_state(env=env)
    #  s.inspect.b('instruction', when=angr.BP_BEFORE, action=track_instructions)
    sm = p.factory.simulation_manager(s)
    sm.run()

    traces = {}
    for d in sm.deadended:
        traces[d] = []
        for a in d.history.bbl_addrs:
            traces[d].append(d.block(a, num_inst=1))
            #  d.block(a, num_inst=1).pp()
            #  print(d.block(a, num_inst=1).disassembly)

    return traces

# traces { state: block }
# suppose stdin is sec
def simple_filter(traces, env={}):
    filtered = {}
    for s, b in traces.items():
        print(stdin_dump(s))
        print(env_dump(s, env))
        input_data = s.posix.stdin.read(2, s.posix.stdin.size)
        print(input_data)
        print(s.posix.stdin.content)
        lengths = [s.solver.eval(x[1]) for x in s.posix.stdin.content]
        sizes = [x[0].size() for x in s.posix.stdin.content]
        print("lenghts", lengths)
        print("sizes: ", sizes)
        a = [
            x[0][: size - i * s.arch.byte_width]
            for i, size, x in zip(lengths, sizes, s.posix.stdin.content)
        ]
        print("a: ", a)
        constraints = s.solver.constraints
        #  for c in constraints:
            #  sc = claripy.simplify(c)
            #  print(c)
            #  print(type(sc.to_claripy()))
            #  print(type(c))
        #  print(s.posix.environ)
        #  print(s.solver.eval(s.posix.environ, cast_to=bytes))
        print("----", type(s.solver.constraints))
        for k in env:
            bs2 = s.solver.eval(env[k], cast_to=bytes)
            #  print("-------", k, "------", bs2)
        #  input_data = s.posix.stdin.load(0, s.posix.stdin.size)
        #  bs = s.solver.eval(input_data[0], cast_to=bytes)
        #  print(s.solver.eval(symbolic_var, cast_to=bytes))
        #  print('---')
    return filtered

def stdin_dump(state):
    return state.posix.dumps(0)

#  def stdin_dump_list(state):
    #  lengths = [state.solver.eval(x[1]) for x in state.posix.stdin.content]
    #  sizes = [x[0].size() for x in state.posix.stdin.content]
    #  return [
        #  b"" if i == 0 else state.solver.eval(x[0][: size - i * state.arch.byte_width], cast_to=bytes)
        #  for i, size, x in zip(lengths, sizes, state.posix.stdin.content)
    #  ]

def stdin_constraints(state):
    lengths = [state.solver.eval(x[1]) for x in state.posix.stdin.content]
    sizes = [x[0].size() for x in state.posix.stdin.content]
    return [
        x[0][: size - i * state.arch.byte_width]
        for i, size, x in zip(lengths, sizes, state.posix.stdin.content)
    ]

def env_dump(state, env={}):
    return {k: state.solver.eval(v, cast_to=bytes) for k, v in env.items()}


BSIZE = 8
DEFAULT_ENV = {
    "PATH"  : claripy.BVS('path_val', 8 * BSIZE),
    "AUTH"  : claripy.BVS('auth_val', 8 * BSIZE),
    "TOKEN" : claripy.BVS('token_val', 8 * BSIZE),
}

if __name__ == '__main__':
    path = 'examples/branches'
    my_env = dict (
        DEFAULT_ENV, **{
        "BRANCHES": claripy.BVS('br_val', 8 * BSIZE),
    })

    traces = simple_tracer(path, my_env)
    filtered = simple_filter(traces, my_env)

