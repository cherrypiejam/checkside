import sys
import angr
import claripy
import argparse

from models.base import Base
from models.stdin_insts import StdinInsts
from models.stdin_cycles import StdinCycles

MODEL_TYPES = {
    0: StdinInsts,
    1: StdinCycles,
}

BSIZE = 8
DEFAULT_ENV = {
    "PATH"  : claripy.BVS('path_val', 8 * BSIZE),
    "TOKEN" : claripy.BVS('token_val', 8 * BSIZE),
}


def checkside(m: Base):
    return m.analyse(m.filter(m.trace()))


if __name__ == '__main__':


    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--path', type=str, required=True)
    parser.add_argument('-m', '--model', type=int, default=0)
    parser.add_argument('-t', '--table', type=str, required=False)

    args = parser.parse_args()
    my_env = dict (
        DEFAULT_ENV, **{
        "MYENV": claripy.BVS('myenv_val', 8 * BSIZE),
    })

    model = MODEL_TYPES[args.model]
    model_obj =\
        model(args.path, env=my_env, inst_table_path=args.table)

    results = checkside(model_obj)
    for r in results:
        print(r)

