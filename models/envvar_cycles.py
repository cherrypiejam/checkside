import angr
import claripy
import csv

from models.base import Base
import utils, timing

"""

Timing Model: # core clock cycles

Secrecy Model: environment variables

"""

class EnvVarCycles(Base):
    def __init__(self, path, env={}, **kwargs):
        self.path = path
        self.env = env
        if kwargs['target_envvar'] in self.env:
            self.target_envvar_name = kwargs['target_envvar']
            self.target_envvar = self.env[kwargs['target_envvar']]
        else:
            raise Exception('target environment variable does not exist')
        with open(kwargs['inst_table_path'], 'r') as f:
            self.inst_table = list(csv.DictReader(f))

    def trace(self):
        print('tracing...')

        p = angr.Project(self.path, auto_load_libs=False)
        s = p.factory.entry_state(env=self.env)
        sm = p.factory.simulation_manager(s)
        sm.run()

        return {
            d : [
                d.block(a)
                for a in d.history.bbl_addrs
            ]
            for d in sm.deadended
        }


    def filter(self, traces):
        print('filtering...', len(traces))
        return traces

    def calc_cycles(self, trace):
        cycles, fails = timing.calc_trace_cycles(trace, self.inst_table)
        return sum(cycles) + len(fails)

    def analyse(self, traces):
        print('analysing...')

        paired = [
            (p[0], p[1]) if len(traces[p[0]]) < len(traces[p[1]]) else (p[1], p[0])
            for p in utils.combinations(list(traces.keys()), 2)
            if self.calc_cycles(traces[p[0]])
                != self.calc_cycles(traces[p[1]])
        ]

        filtered = [
            (fst, snd)
            for fst, snd in paired
            if utils.is_unsat(
                self.target_envvar,
                utils.constraints(fst, list(self.target_envvar.variables)),
                utils.constraints(snd, list(self.target_envvar.variables)),
            )
        ]

        results = [
            ({ 'envs': utils.env_dump(fst, {self.target_envvar_name: self.target_envvar}),
               '# instructions': self.calc_cycles(traces[fst])}
            ,{ 'envs': utils.env_dump(snd, {self.target_envvar_name: self.target_envvar}),
               '# instructions': self.calc_cycles(traces[snd])})
            for fst, snd in filtered
        ]

        return results


