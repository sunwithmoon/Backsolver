import logging
from itertools import islice
from claripy import ast

from angr.exploration_techniques import ExplorationTechnique

l = logging.getLogger(name=__name__)

def crc(prev, cur):
    prev = (prev >> 4) ^ (prev << 8)
    prev &= 65535
    prev = prev >> 1
    cur = (cur >> 4) ^ (cur << 8)
    cur &= 65535
    return cur ^ prev

class DrillerCore(ExplorationTechnique):
    """
    An exploration technique that symbolically follows an input looking for new
    state transitions.

    It has to be used with Tracer exploration technique. Results are put in
    'diverted' stash.
    """

    def __init__(self, trace, fuzz_bitmap=None, optimistic_solving=False, iiv_solver=None, cfg=None):
        """
        :param trace      : The basic block trace.
        :param fuzz_bitmap: AFL's bitmap of state transitions. Defaults to saying every transition is worth satisfying.
        """

        super(DrillerCore, self).__init__()
        self.trace = trace
        self.fuzz_bitmap = fuzz_bitmap or b"\xff" * 65536
        self.optimistic_solving = optimistic_solving
        self.iiv_solver = iiv_solver
        self.cfg = cfg if cfg is not None else self.project.analyses.CFGFast()

        # Set of encountered basic block transitions.
        self.encounters = set()
        self.succ_solve = set() # save crc that has been solved

    def setup(self, simgr):
        self.project = simgr._project

        # Update encounters with known state transitions.
        self.encounters.update(zip(self.trace, islice(self.trace, 1, None)))


    def optimistic_satisfiable(self, state, constraints, target: ast.Bool, oldcon_cache_keys):

        def get_arg(expr):
            if type(expr) in (ast.bv.BV,):
                return [expr]
            if type(expr) == ast.bool.Bool and expr.concrete:
                return [expr]

            args = []
            for arg in expr.args:
                    args += get_arg(arg)
            return args

        relevant_variables = set()
        for arg in target.recursive_leaf_asts:
            if not arg.concrete:
                relevant_variables.add(arg)

        relevant_constraints = []
        irrelevant_constraints = []
        for c in constraints:
            ir = True
            for arg in c.recursive_leaf_asts:
                if arg in relevant_variables:
                    relevant_constraints.append(c)
                    ir = False
                    break
            if ir:
                irrelevant_constraints.append(c)

        for i in range(len(relevant_constraints)):
            state.solver.reload_solver(irrelevant_constraints + relevant_constraints[i:])
            if state.solver.satisfiable():
                state.solver.constraints.sort(key=lambda x: oldcon_cache_keys.index(x.cache_key))
                return True
        return False


    def has_child_hit(self, block_addr):
        """
        Check if the child of block has been hit.
        """
        func_addr = self.cfg.functions.floor_func(block_addr).addr
        func_cfg = self.cfg.kb.functions[func_addr].transition_graph

        for node in func_cfg.succ:
            if node.addr != block_addr:
                continue
            node_succ = func_cfg.succ[node]
            if not node_succ:
                return True
            for child_node in node_succ:
                if node_succ[child_node]['type'] in ('transition', 'call'):
                    if self.fuzz_bitmap[crc(node.addr, child_node.addr)] ^ 0xff:
                        return True
        return False



    def step(self, simgr, stash='active', **kwargs):
        simgr.step(stash=stash, **kwargs)

        # Mimic AFL's indexing scheme.
        if 'missed' in simgr.stashes and simgr.missed:
            # A bit ugly, might be replaced by tracer.predecessors[-1] or crash_monitor.last_state.
            prev_addr = simgr.one_missed.history.bbl_addrs[-1]
            prev_loc = prev_addr
            prev_loc = (prev_loc >> 4) ^ (prev_loc << 8)
            prev_loc &= len(self.fuzz_bitmap) - 1
            prev_loc = prev_loc >> 1

            for state in simgr.missed:
                cur_loc = state.addr
                cur_loc = (cur_loc >> 4) ^ (cur_loc << 8)
                cur_loc &= len(self.fuzz_bitmap) - 1

                hit = (bool(self.fuzz_bitmap[cur_loc ^ prev_loc] ^ 0xff) and self.has_child_hit(state.addr)) or ((cur_loc ^ prev_loc) in self.succ_solve)

                transition = (prev_addr, state.addr)
                mapped_to = self.project.loader.find_object_containing(state.addr).binary

                l.debug("Found %#x -> %#x transition.", transition[0], transition[1])

                # if not hit and transition not in self.encounters and not self._has_false(
                #         state) and mapped_to != 'cle##externs':
                if not hit and transition not in self.encounters and mapped_to != 'cle##externs':

                    oldcon_cache_keys = []
                    for con in state.solver.constraints:
                        oldcon_cache_keys.append(con.cache_key)
                    last_constraint = state.solver.constraints[-1]
                    if last_constraint.concrete:
                        fp = open("/dev/shm/work/concrete_constraint.txt", "a")
                        fp.write("(0x%x, 0x%x)\n" % (transition[0], transition[1]))
                        fp.close()
                    sat = state.satisfiable()
                    state.preconstrainer.remove_preconstraints(simplify=not self.optimistic_solving)
                    if self.optimistic_solving:
                        # sort the constraints
                        state.solver.constraints.sort(key=lambda x : oldcon_cache_keys.index(x.cache_key))


                    if state.satisfiable() or (self.optimistic_solving and self.optimistic_satisfiable(state, state.solver.constraints, last_constraint, oldcon_cache_keys)):
                        # check iiv_solver
                        if self.iiv_solver and self.iiv_solver.pattern.findall(repr(last_constraint)):
                            iiv_set = set(self.iiv_solver.pattern.findall(repr(last_constraint)))
                            if iiv_set:
                                if self.iiv_solver.solve(last_constraint, iiv_set, state):
                                    self.succ_solve.add(cur_loc ^ prev_loc)
                                    simgr.stashes['diverted'].extend(self.iiv_solver.solved_state)
                                    target = last_constraint
                                    last2 = None
                                    for con in state.solver.constraints[:-1:-1]:
                                        if set(self.iiv_solver.pattern.findall(repr(con))) & iiv_set:
                                            iiv_set.update(self.iiv_solver.pattern.findall(repr(con)))
                                            target = state.solver.And(target, con)
                                            if last2 is None:
                                                last2 = state.solver.And(target, con)
                                    if last2 and self.iiv_solver.solve(last2, iiv_set, state):
                                        simgr.stashes['diverted'].extend(self.iiv_solver.solved_state)
                                    # if self.iiv_solver.solve(target, iiv_set, state):
                                    #     simgr.stashes['diverted'].extend(self.iiv_solver.solved_state)
                                else:
                                    l.debug("State at %#x is not satisfiable when trace back for constraint: {}".format(last_constraint),
                                            transition[1])
                                    return simgr


                        else:
                            # A completely new state transition.
                            self.succ_solve.add(cur_loc ^ prev_loc)
                            l.debug("Found a completely new transition, putting into 'diverted' stash.")
                            simgr.stashes['diverted'].append(state)
                            self.encounters.add(transition)

                    else:
                        l.debug("State at %#x is not satisfiable.", transition[1])

                elif self._has_false(state):
                    l.debug("State at %#x is not satisfiable even remove preconstraints.", transition[1])

                else:
                    l.debug("%#x -> %#x transition has already been encountered.", transition[0], transition[1])

        return simgr

    #
    # Private methods
    #

    @staticmethod
    def _has_false(state):
        # Check if the state is unsat even if we remove preconstraints.
        claripy_false = state.solver.false
        if state.scratch.guard.cache_key == claripy_false.cache_key:
            return True

        for c in state.solver.constraints:
            if c.cache_key == claripy_false.cache_key:
                return True

        return False
