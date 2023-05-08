import sys
import angr
import claripy
import argparse

from models.base          import Base
from models.stdin_insts   import StdinInsts
from models.stdin_cycles  import StdinCycles
from models.envvar_insts  import EnvVarInsts
from models.envvar_cycles import EnvVarCycles

MODEL_TYPES = {
    0: StdinInsts,
    1: StdinCycles,
    2: EnvVarInsts,
    3: EnvVarCycles,
}

BSIZE = 8
DEFAULT_ENV = {
    #  "PATH"  : claripy.BVS('path_val', 8 * BSIZE),
    "TOKEN" : claripy.BVS('token_val', 1 * BSIZE),
}


def checkside(m: Base):
    return m.analyse(m.filter(m.trace()))


# Example:
# python checkside.py -p examples/build/branch -m 0 -e TOKEN
if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--path',   type=str, required=True)
    parser.add_argument('-m', '--model',  type=int, default=0)
    parser.add_argument('-t', '--table',  type=str, required=False)
    parser.add_argument('-e', '--envvar', type=str, required=False)

    args = parser.parse_args()

    my_env = dict(DEFAULT_ENV)
    if args.envvar and args.envvar not in my_env:
        my_env[args.envvar] = claripy.BVS(f'{args.envvar.lower()}_val', 8 * BSIZE)

    model = MODEL_TYPES[args.model]
    model_obj =\
        model(args.path,
              env=my_env,
              inst_table_path=args.table,
              target_envvar=args.envvar)

    results = checkside(model_obj)
    for r in results:
        print(r)

