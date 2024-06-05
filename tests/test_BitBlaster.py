import angr
import binascii
import claripy

flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(0x42)]
def mem_write(state):
    if state.addr != 0x400B86:
        return
    # print(state.inspect.mem_write_expr)



def main():
    p = angr.Project("/tmp/fuzz/example/cb-multios/build64/challenges/BitBlaster/BitBlaster")

    inputstr = [0x30] + [0x3f, 0x3e] * 0x20 + [0xff]

    flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])
    state = p.factory.entry_state(
        args=['./BitBlaster'],
        add_options={angr.options.SYMBOLIC_WRITE_ADDRESSES},
        stdin=flag,
    )
    state.inspect.b('mem_write', angr.BP_AFTER, action=mem_write)

    simgr = p.factory.simulation_manager(state)
    simgr.use_technique(angr.exploration_techniques.ManualMerge4Step([0x400E07],wait_counter=1024))

    # simgr.explore(find=0x400EF6)
    # s = simgr.found[0]
    # simgr = p.factory.simulation_manager(s)
    count = 0
    from guppy import hpy
    h = hpy()
    while simgr.active:
        simgr.step()
        for s in list(simgr.active):
            if s.addr in (0x400EE1, 0x400DFA):
                simgr.active.remove(s)
        print(simgr.active)
        if simgr.active[0].addr == 0x400E10:
            count += 1
            if count < 13:
                continue
            s = simgr.active[0]
            print(s.solver.eval(s.mem[0x6015D0+31*4].int.resolved))
            print(state.satisfiable(extra_constraints=[s.mem[0x6015D0+31*4].int.resolved==0]))
            # exit()
            # for i in range(32):
            #     print(s.mem[0x6015D0+i*4].int)
        # print(simgr.active)
    exit()
    s.add_constraints(s.regs.edi == 0x3f)
    simgr = p.factory.simulation_manager(s)
    simgr.explore(find=0x400DED)
    s = simgr.found[0]
    simgr = p.factory.simulation_manager(s)
    simgr.explore(find=0x400DF5)
    s = simgr.found[0]
    simgr = p.factory.simulation_manager(s)
    simgr.explore(find=0x400DED)
    s = simgr.found[0]
    simgr = p.factory.simulation_manager(s)
    simgr.explore(find=0x400DF5)
    s = simgr.found[0]
    import IPython
    IPython.embed()

    # while True:
    #     simgr.step()
    #     if len(simgr.active) == 0:
    # found = simgr.found[0]


if __name__ == '__main__':
    import logging

    # logging.getLogger('angr.sim_manager').setLevel(logging.DEBUG)
    print(main())
