import logging
from itertools import islice
import time
from angr.exploration_techniques import ExplorationTechnique
import re
import string
from functools import reduce
import angr
import re
import archinfo

import os

l = logging.getLogger(name=__name__)
write_dict = None
write_info = None
iiv_solver = None
out_entry_dict = None
trace_back_dict = {}
order = 0

class IIVSolver(ExplorationTechnique):
    """
    Indirect Influencing  Variables Solver
    """

    def __init__(self, proj, iiv_info=None, continuous_solve=False):
        """
        :param iiv_info   : information of indirect influencing variables
        """

        super().__init__()
        self.iiv_info = iiv_info
        self.proj = proj
        self.filename = os.path.basename(proj.filename)
        self.snapshots = {}
        self.branches = {}
        self.backtrack_addr = set()
        self.check_addr = {}
        self.solve_info = {}
        self.write_dict = {} # to trace back ahead of the loop according to the write instructions' addr
        self.continuous_solve = continuous_solve

    def setup(self, simgr):
        global write_dict, iiv_solver, write_info, out_entry_dict, trace_back_dict

        self.pattern = re.compile(r"(iiv_[\w]+)")
        self.project = simgr._project
        for branch_addr, bbl_info in self.iiv_info.items():
            backtrack_addr = min(bbl_info["backtrack_addr"])
            if backtrack_addr not in self.solve_info:
                self.solve_info[backtrack_addr] = {
                    "check_addr" : set(bbl_info["check_addr"]),
                    "merge_addr" : set(bbl_info["merge_addr"])
                }
            else:
                self.solve_info[backtrack_addr]["merge_addr"].update(set(bbl_info["merge_addr"]))

            if branch_addr not in self.branches:
                self.branches[branch_addr] = {
                    "addr_range" : bbl_info["addr_range"],
                    "backtrack_addr" : bbl_info["backtrack_addr"],
                    "check_addr": bbl_info["check_addr"],
                    "merge_addr" : bbl_info["merge_addr"],
                }
                self.backtrack_addr.update(set(bbl_info["backtrack_addr"]))
                for out_addr in bbl_info["check_addr"]:
                    if out_addr not in self.check_addr:
                        self.check_addr[out_addr] = {min(bbl_info["backtrack_addr"])}
                    else:
                        self.check_addr[out_addr].add(min(bbl_info["backtrack_addr"]))




            for ins_info in bbl_info["write_ins"]:
                write_ins = ins_info[0]
                if write_ins not in self.write_dict:
                    self.write_dict[write_ins] = set(bbl_info["backtrack_addr"])
                else:
                    self.write_dict[write_ins] |= set(bbl_info["backtrack_addr"])


        self.write_info = {}
        '''
        use write_info to store information of write locations
        entry is the lowest addr of backtrack_addr
        {
            entry:{
                str(write_loc)+str(size):{
                    "write_ins"     : {write_ins},
                    "write_expr"    : write_expr,
                    "write_loc"     : BVV,
                    "size"          : int,
                    "backtrack_addr"       : {backtrack_addr},
                    "order"         : int,
                    "sym_value"     : symbolic_value
                }
            }
        }
        '''

        self.symbol_names = {}
        '''
        store the backtrack addr of symbol names for backtracking
        '''

        self.trace_back_dict = trace_back_dict
        write_dict = self.write_dict
        write_info = self.write_info
        out_entry_dict = self.check_addr
        iiv_solver = self

        def write_hook(state):
            global write_dict, iiv_solver, order, write_info, trace_back_dict
            if state.addr not in write_dict:
                return
            if not state.inspect.mem_write_expr.concrete:
                if not "iiv_" in str(state.inspect.mem_write_expr):
                    l.error("write expression (%r) is not concrete at 0x%x", state.inspect.mem_write_expr, state.addr)
                    return

            write_loc = state.inspect.mem_write_address
            write_size = state.inspect.mem_write_length if state.inspect.mem_write_length else state.inspect.mem_write_expr.length//8
            assert (type(write_loc)==int or type(write_loc.args[0]) == int) and type(write_size) == int
            if type(write_loc) != int:
                write_loc = write_loc.args[0]
            write_loc_size = hex(write_loc) + '_' + str(write_size)


            entry = min(write_dict[state.addr])
            if entry not in write_info:
                write_info[entry] = {}
            if write_loc_size not in write_info[entry]:
                iiv_sym = state.solver.BVS("iiv_0x{:x}_{}_{}".format(write_loc, write_size, order), write_size * 8)
                write_info[entry][write_loc_size] = {
                    "write_ins"     : {state.addr},
                    "write_loc"     : write_loc,
                    "size"          : write_size,
                    "write_expr"    : state.inspect.mem_write_expr,
                    "backtrack_addr"       : write_dict[state.addr],
                    "order"         : order,
                    "sym_value"     : iiv_sym
                }
            else:
                # in the same loop
                write_info[entry][write_loc_size]["write_ins"].add(state.addr)
                write_info[entry][write_loc_size]["write_expr"] = state.inspect.mem_write_expr
                write_info[entry][write_loc_size]["order"] = order
                iiv_sym = state.solver.BVS("iiv_0x{:x}_{}_{}".format(write_loc, write_size, order), write_size * 8)
                write_info[entry][write_loc_size]["sym_value"] = iiv_sym
            l.info("at write ins 0x%x: write to 0x%x with %r", state.addr, write_loc, state.inspect.mem_write_expr)
            state.preconstrainer.preconstrain(0, iiv_sym - state.inspect.mem_write_expr)
            state.memory.store(write_loc, iiv_sym, endness=archinfo.Endness.LE, inspect=False)
            trace_back_dict[list(iiv_sym.variables)[0]] = {
                "backtrack_addr": write_dict[state.addr],
                "iiv": iiv_sym
            }
            order += 1

        self.bp_list = []
        for state in simgr.active:
            self.bp_list.append(('mem_write', state.inspect.b('mem_write', when=angr.BP_AFTER, action=write_hook)))

    def step(self, simgr, stash='active', **kwargs):

        for state in simgr.active:
            if state.addr in self.backtrack_addr:
                # take snapshots before stepping into a loop
                if state.addr not in self.snapshots:
                    self.snapshots[state.addr] = [state.copy()]
                else:
                    self.snapshots[state.addr].append(state.copy())

        simgr.step(stash=stash, **kwargs)

        return simgr

    def trace_back(self, constraint, iiv_name, iiv, in_state, loop_entry, branch_addr, start=True, end=False, is_loop=True):
        """

        :param constraint:
        :param iiv:
        :param in_state:
        :param loop_entry:
        :return: True if the constraint could be satisfied, else False
        """

        def recursive_replace(expr, var_name, old_var, new_var):

            if not hasattr(expr, "args"):
                return expr

            new_exp = []
            for arg in expr.args:
                met = False
                if hasattr(arg, "args"):
                    if type(arg.args[0]) == str and arg.args[0] == var_name:
                        new_exp.append(new_var)
                        met = True
                if not met:
                    new_exp.append(recursive_replace(arg, var_name, new_var))
            expr.args = tuple(new_exp)
            return expr

        def func_return(s):
            s.globals['call_level'] -= 1
            if s.globals['call_level'] < 0:
               # make the state unsat
               s.regs.pc = 0
        def into_func(s):
            s.globals['call_level'] += 1

        # def replace_variable(expr, old_name, new):
        #     for arg in expr.args:

        merge_info =  self.solve_info[loop_entry]
        if start:
            in_state = in_state.copy()
            in_state.preconstrainer.remove_preconstraints(simplify=False)
            for event_type, bp in self.bp_list:
                in_state.inspect.remove_breakpoint(event_type, bp)
            if angr.sim_options.UNICORN in in_state.options:
                in_state.options.remove(angr.sim_options.UNICORN)

        if not self.continuous_solve:
            in_state.globals['call_level'] = 0
            in_state.inspect.b('call', angr.BP_AFTER, action=into_func)
            in_state.inspect.b('return', angr.BP_BEFORE, action=func_return)

        simgr = self.proj.factory.simulation_manager(in_state)
        # simgr.use_technique(angr.exploration_techniques.Oppologist())
        from .manual_merge_for_step import ManualMerge4Step
        simgr.use_technique(ManualMerge4Step(list(merge_info["merge_addr"])))
        iiv_addr = int(iiv_name.split('_')[1], 16)
        iiv_size = int(iiv_name.split('_')[2])
        count = 0
        found = False
        force_choice = {}
        while simgr.active:
            simgr.step()




            for state in list(simgr.active):
                if state.history.addr in force_choice:
                    if state.addr != force_choice[state.history.addr]:
                        simgr.move(from_stash='active', to_stash='deadended', filter_func=lambda s: s is state)
                        continue


                if state.addr in merge_info["check_addr"] | {branch_addr}:
                    iiv_cur = state.memory.load(iiv_addr, iiv_size, endness=archinfo.Endness.LE)
                    if self.continuous_solve and not is_loop:
                        state.simplify()
                        if end:
                            l.info("start solving {}".format(constraint))
                            new_con = constraint.replace(iiv, iiv_cur)
                            l.info("new constraint: {:.200}".format(str(new_con)))
                            res = state.satisfiable(extra_constraints=[new_con])
                            if res:
                                l.info("iiv solved!")
                                state.add_constraints(new_con)
                                state.simplify()
                                self.solved_state.append(state.copy())

                            return state, res
                        sm = self.proj.factory.simulation_manager(state)
                        sm.explore(find=branch_addr)
                        if sm.found:
                            state = sm.found[0]

                            return state, True
                        else:
                            l.error("Failed to reach {} from {}".format(hex(branch_addr), state))
                            return

                    new_con = constraint.replace(iiv, iiv_cur)
                    if state.satisfiable(extra_constraints=[new_con]):
                        l.info("iiv solved!")
                        state.add_constraints(new_con)
                        state.simplify()
                        self.solved_state.append(state.copy())
                        l.info("Now exploring to the branch 0x{:x}...".format(branch_addr))
                        sm = self.proj.factory.simulation_manager(state)
                        sm.explore(find=branch_addr)
                        if sm.found:
                            l.info("reach the branch!")
                            self.solved_state.append(sm.found[0].copy())
                        else:
                            l.info("failed to reach the branch!")

                        found = True
                    if state.addr in merge_info["check_addr"]:
                        simgr.active.remove(state)
            count += 1
            if count >= 1024:
                break
        return found




    def solve(self, constraint, iiv_set, branch_state):
        """
        try to trace back and solve the constraint, when get a result, add input constraints and save the state to self.solved_state
        :param constraint: the met constraint which is relevant with iiv in iiv_set
        :param iiv_list: iiv set in the constraint
        :param state:  save the result in the form of adding input constraint
        :return:c
        """
        l.info("--------iiv_solve-----------\nstate:{}\n{}: {}\n".format( branch_state,self.filename, repr(constraint)))

        branch_addr = branch_state.history.addr
        con_solve_entry = set()
        if self.continuous_solve:
            # First, find the iiv that influence the branch

            for iiv_branch in self.iiv_info:
                if self.iiv_info[iiv_branch]["type"] == 'BRANCH' and branch_addr in self.iiv_info[iiv_branch]["influent_branch"]:
                    con_solve_entry.add(list(self.iiv_info[iiv_branch]["backtrack_addr"])[0])

            # Second, find the address between trackback and current branch_state
        earliest_backtrack = None
        earliest_backtrack_index = None
        if self.continuous_solve:
            for addr in con_solve_entry:
                if addr not in branch_state.history.bbl_addrs.hardcopy:
                    continue
                index = branch_state.history.bbl_addrs.hardcopy.index(addr)
                if earliest_backtrack_index is None or index < earliest_backtrack_index:
                    earliest_backtrack_index = index
                    earliest_backtrack = addr


        self.solved_state = []
        for iiv_name in iiv_set:
            assert iiv_name in self.trace_back_dict
            entry = min(self.trace_back_dict[iiv_name]["backtrack_addr"])
            iiv = self.trace_back_dict[iiv_name]["iiv"]
            for backtrack_addr in self.trace_back_dict[iiv_name]["backtrack_addr"]:
                if earliest_backtrack is not None:
                    backtrack_addr = earliest_backtrack
                if backtrack_addr in self.snapshots:
                    for state in self.snapshots[backtrack_addr]:
                        l.info("backtracking to {}".format(state))
                        for iiv_branch in self.iiv_info:
                            if backtrack_addr in self.iiv_info[iiv_branch]["backtrack_addr"]:
                                break
                        if not self.continuous_solve or self.iiv_info[iiv_branch]['type'] != 'BRANCH':
                            if self.trace_back(constraint, iiv_name, iiv, state, entry, branch_addr):
                                break
                        else:
                            start = len(state.history.bbl_addrs.hardcopy) + 1
                            first = True
                            index = start
                            while index < len(branch_state.history.bbl_addrs.hardcopy):
                                cur = branch_state.history.bbl_addrs.hardcopy[index]
                                if index + 1 < len(branch_state.history.bbl_addrs.hardcopy):
                                    next = branch_state.history.bbl_addrs.hardcopy[index + 1]
                                else:
                                    next = None
                                for next_entry in con_solve_entry:
                                    if next_entry == cur or (next != next_entry and self.proj.factory.block(next_entry).size+next_entry == self.proj.factory.block(cur).size+cur):
                                        if next_entry != cur and next:
                                            if self.proj.factory.block(next_entry).size+next_entry == self.proj.factory.block(next).size+next and next != cur:
                                                index += 1
                                        target = next_entry
                                        l.info("Now backtrack to 0x{:x} to explore to the branch 0x{:x}...".format(backtrack_addr, target))
                                        state, succ = self.trace_back(constraint, iiv_name, iiv, state, backtrack_addr, target, start=first, is_loop=False)
                                        l.info("---------------")
                                        first = False
                                        backtrack_addr = target
                                        break
                                index += 1
                            state, succ = self.trace_back(constraint, iiv_name, iiv, state, backtrack_addr, branch_addr, start=first, end=True, is_loop=False)
                            if succ:
                                break



                    else:
                        continue
                    break

        return self.solved_state
