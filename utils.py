import claripy

def combinations(l, k, acc=[]):
    if len(acc) == k:
        return [acc]

    return [
        c
        for i, e in enumerate(l)
        for c in combinations(l[i+1:], k, [*acc, e])
    ]


#  def stdin_dump(state):
    #  return state.posix.dumps(0)

def stdin_dump(state):
    lengths = [state.solver.eval(x[1]) for x in state.posix.stdin.content]
    sizes = [x[0].size() for x in state.posix.stdin.content]
    return [
        b"" if i == 0 else state.solver.eval(x[0][: size - i * state.arch.byte_width], cast_to=bytes)
        for i, size, x in zip(lengths, sizes, state.posix.stdin.content)
    ]

def stdin_bitvectors(state):
    lengths = [state.solver.eval(x[1]) for x in state.posix.stdin.content]
    sizes = [x[0].size() for x in state.posix.stdin.content]
    return [
        x[0][: size - i * state.arch.byte_width]
        for i, size, x in zip(lengths, sizes, state.posix.stdin.content)
    ]

def stdin_variables(state):
    return [
        v
        for bv in stdin_bitvectors(state)
        for v in bv.variables
    ]

def env_dump(state, env={}):
    return {k: state.solver.eval(v, cast_to=bytes) for k, v in env.items()}


def constraints(state, vars):
    remaining = [ *vars ]
    visited = set()
    constraints = set()

    while remaining:
        var = remaining.pop()
        visited.add(var)
        #  print(var)
        for c in state.solver.constraints:
            if var in c.variables:
                constraints.add(c)
                remaining = [ *remaining, *[ v for v in c.variables if v not in visited ] ]

    return list(constraints)

def eval(var, *args):
    s = claripy.Solver()
    for c in args:
        s.add(c)
    return s.eval(var, 1)

def is_unsat(var, *args):
    try:
        eval(var, *args)
    except claripy.UnsatError:
        return True
    return False
