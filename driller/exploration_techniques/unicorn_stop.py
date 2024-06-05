from angr.exploration_techniques import ExplorationTechnique
from claripy import ast
import logging
from functools import reduce

l = logging.getLogger(name=__name__)
class UnicornStop(ExplorationTechnique):


    def __init__(self, stop_points=None, save_addr=None, snapshot=None, recursive=True):
        '''
        Note: stop_points shouldn't be the start of a block!

        '''
        super(UnicornStop, self).__init__()
        self.stop_points = stop_points
        self.recursive = recursive
        self.save_addr = save_addr if save_addr is not None else []
        self.snapshots = snapshot if snapshot is not None else {}
        self.tmp = "US_tmp"

    def setup(self, simgr):
        simgr.stashes[self.tmp] = []

    def tmp_step(self, simgr, state, extra_stop_points, **kwargs):
        # step until block start to avoid fake new path
        succs_dict = simgr.step_state(state, extra_stop_points=extra_stop_points, **kwargs)
        sat_succs = succs_dict[None]  # satisfiable states
        for state in list(sat_succs):
            if state.addr in self.stop_points:
                # Note: stop_points shouldn't be the start of a block!
                assert len(sat_succs) == 1
                if state.addr in self.save_addr:
                    # take snapshots before stepping into a loop
                    if state.addr not in self.snapshots:
                        self.snapshots[state.addr] = [state.copy()]
                    else:
                        self.snapshots[state.addr].append(state.copy())
                succs_dict = self.tmp_step(simgr, state, extra_stop_points=extra_stop_points, **kwargs)

        return succs_dict

    def step_state(self, simgr, state, **kwargs):
        stops = set(kwargs.pop('extra_stop_points', ())) | self.stop_points
        if self.recursive:
            succs_dict = self.tmp_step(simgr, state, extra_stop_points=stops, **kwargs)
        else:
            succs_dict = simgr.step_state(state, extra_stop_points=stops, **kwargs)
        return  succs_dict
