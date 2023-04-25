import sys
import angr
import claripy

from models.base import Base
from models.stdin_insts import StdinInsts
from models.stdin_cycles import StdinCycles


BSIZE = 8
DEFAULT_ENV = {
    "PATH"  : claripy.BVS('path_val', 8 * BSIZE),
    "TOKEN" : claripy.BVS('token_val', 8 * BSIZE),
}


def checkside(m: Base):
    return m.analyse(m.filter(m.trace()))


if __name__ == '__main__':

    try:
        path = sys.argv[1]
    except:
        path = 'examples/build/checksum'

    my_env = dict (
        DEFAULT_ENV, **{
        "BRANCHES": claripy.BVS('br_val', 8 * BSIZE),
    })

    #  result = checkside(DefaultModel(path, my_env))
    result = checkside(StdinCycles(path, 'resources/intel_skylake_instruction_table_2022.csv', my_env))
    print(result)

