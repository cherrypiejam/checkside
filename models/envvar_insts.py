import angr
import claripy

from models.base import Base
import utils, timing

"""

Timing Model: # instructions

Secrecy Model: environment variables

"""

class EnvVarInsts(Base):
    def __init__(self, path, env={}, **kwargs):
        self.path = path
        self.env = env
        if kwargs['target_envvar'] in self.env:
            self.target_envvar = self.env[kwargs['target_envvar']]
        else:
            raise Exception('target environment variable does not exist')

    def trace(self):

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

        # TODO filter stdin related...
        #  print([[self.target_envvar.variables]])
        #  print(utils.env_dump)

        return traces


    def analyse(self, traces):

        paired = [
            (p[0], p[1]) if len(traces[p[0]]) < len(traces[p[1]]) else (p[1], p[0])
            for p in utils.combinations(list(traces.keys()), 2)
            if timing.calc_trace_instructions(traces[p[0]])
                != timing.calc_trace_instructions(traces[p[1]])
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


        # TODO What exactly do we want
        results = [
            ({ 'inputs': fst.posix.dumps(0), '# instructions': timing.calc_trace_instructions(traces[fst])}
            ,{ 'inputs': snd.posix.dumps(0), '# instructions': timing.calc_trace_instructions(traces[snd])})
            for fst, snd in filtered
        ]

        return results


