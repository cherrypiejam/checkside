import angr

def track_instructions(state):
    addr = state.inspect.instruction
    state.block(addr, num_inst=1).pp()

def simple_tracer(path):
    p = angr.Project(path, auto_load_libs=False)
    s = p.factory.entry_state()
    s.inspect.b('instruction', when=angr.BP_BEFORE, action=track_instructions)
    sm = p.factory.simulation_manager(s)
    sm.run()

    traces = {}
    for d in sm.deadended:
        traces[d] = []
        for a in d.history.bbl_addrs:
            traces[d].append(d.block(a, num_inst=1))
            d.block(a, num_inst=1).pp()
            print(d.block(a, num_inst=1).disassembly)

    return traces

if __name__ == '__main__':
    path = 'examples/branch'
    ret = simple_tracer(path)

