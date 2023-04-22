
# a trace is a list of basic blocks
def num_instructions(trace):
    return sum([
        b.instructions
        for b in trace
    ])
