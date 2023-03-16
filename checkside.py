import angr

def track_instructions(state):
    addr = state.inspect.instruction
    if addr is not None:
        print('... at ', hex(addr), ' ', )
        state.block(addr, num_inst=1).pp()

def foo(state):
    print('', state.inspect.simprocedure_name)

def check(path):
    p = angr.Project(path, auto_load_libs=False)
    s = p.factory.entry_state()
    s.inspect.b('instruction', when=angr.BP_AFTER, action=track_instructions)
    sm = p.factory.simulation_manager(s)
    sm.run()
    return sm.deadended

if __name__ == '__main__':
    path = 'examples/branch'
    ret = check(path)
    print(ret)

