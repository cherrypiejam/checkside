import sys
import angr
import claripy

from base_model import BaseModel
from default_model import DefaultModel
from my_model_1 import Model


BSIZE = 8
DEFAULT_ENV = {
    "PATH"  : claripy.BVS('path_val', 8 * BSIZE),
    "TOKEN" : claripy.BVS('token_val', 8 * BSIZE),
}


def checkside(m: BaseModel):
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
    result = checkside(Model(path, 'resources/intel_skylake_instruction_table_2022.csv', my_env))
    print(result)

