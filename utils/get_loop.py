import logging
import angr
import claripy
from claripy import ast
import os
import pickle

l = logging.getLogger(name="getloop")
l.setLevel("DEBUG")

class GetLoops:
    def __init__(self, binary, cfg=None):
        self.p = angr.Project(binary)
        self.pickle_path = binary
        self.cfg = cfg

    def add_loop(self, new_loop, func_addr):
    # add new loop
        if func_addr not in self.loops:
            self.loops[func_addr] = []

        for i in range(len(self.loops[func_addr])):
            if self.loops[func_addr][i] & new_loop:
                self.loops[func_addr][i] |= new_loop
                l.debug("merge loop: %r", [hex(addr) for addr in self.loops[func_addr][i]])
                return
        l.debug("add loop: %r", [hex(addr) for addr in new_loop])
        self.loops[func_addr].append(new_loop)

    def identify_func_loops(self, func_addr, func_cfg_succ, node, trace):
        trace.append(node.addr)
        self.visited.add(node.addr)
        for new_node in func_cfg_succ[node]:
            if func_cfg_succ[node][new_node]['type'] not in ('transition','fake_return'):
                continue
            if new_node.addr == node.addr:
                # self-loop
                self.add_loop(set([node.addr]), func_addr)
                continue
            if new_node.addr in trace:
                index = trace.index(new_node.addr)

                # the instruction in the block might be the start instruction of another block
                for addr in self.p.factory.block(node.addr).instruction_addrs:
                    if addr in trace and trace.index(addr) < index:
                        index = trace.index(addr)

                self.add_loop(set(trace[index:]), func_addr)
                continue
            # if new_node.addr in self.visited:
            #     continue
            self.identify_func_loops(func_addr, func_cfg_succ, new_node, trace)
        trace.pop(-1)

    def get_loops(self):
            """
            Identifying the loops of a binary and return the loop entrance addr and addr of bbl in the loop
            :return: [(loop_entrance,[bbl_addr])]
            """
            self.loops = {}
            self.visited = set()
            if not self.cfg:
                # cfg = self._current_p.analyses.CFG(collect_data_references=True, extra_cross_references=True)
                self.cfg = self.p.analyses.CFGFast()

            cfg_func = self.cfg.kb.functions
            for func_addr in cfg_func:
                if func_addr >= self.p.loader.main_object.min_addr and func_addr <= self.p.loader.main_object.max_addr:
                    self.identify_func_loops(func_addr, cfg_func[func_addr].transition_graph.succ, cfg_func[func_addr].startpoint, [])

if __name__ == "__main__":
    gl = GetLoops("/tmp/fuzz/example/cb-multios2/cb-multios/build64/challenges/Music_Store_Client/Music_Store_Client")
    gl.get_loops()
    # print(gl.loops)
    from functools import reduce
    for key in gl.loops:
        print(key)
        for loop in gl.loops[key]:
            print([hex(c) for c in loop])
        # print(gl.loops[key])
        gl.loops[key] = reduce(lambda a, b: a | b, gl.loops[key], set())
    print(gl.loops)
    # loops_path = gl.pickle_path + "_loops.pk"
# with open(loops_path,"wb") as fp:
#     pickle.dump(gl.loops, fp)


