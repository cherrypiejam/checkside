import angr
import claripy

from base_model import BaseModel
from default_model import DefaultModel


BSIZE = 8
DEFAULT_ENV = {
    "PATH"  : claripy.BVS('path_val', 8 * BSIZE),
    "TOKEN" : claripy.BVS('token_val', 8 * BSIZE),
}


def checkside(model: BaseModel, path, env={}):
    trace   = model.trace
    filter  = model.filter
    analyse = model.analyse
    return analyse(trace(filter(path, env), env), env)


if __name__ == '__main__':
    #  path = 'examples/branches'
    path = 'examples/fauxware_elf'
    my_env = dict (
        DEFAULT_ENV, **{
        "BRANCHES": claripy.BVS('br_val', 8 * BSIZE),
    })

    result = checkside(DefaultModel(), path, my_env)
    print(result)

