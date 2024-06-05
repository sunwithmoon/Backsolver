import angr
import logging

l = logging.getLogger("angr.exploration_techniques.manual_merge_for_step")
l.setLevel(logging.DEBUG)
def mystep(simgr):
    i=0
    for i in range(100):
        simgr.step()
        l.debug("IP:%r", [hex(s.regs.ip.args[0]) for s in simgr.stashes["active"]])
        for state in simgr.stashes['active']:
            # if state.regs.rip.args[0]==0x4007e1:
            #     count = state.memory.load(state.regs.rbp - 0x34, 1)
            #     print(state.satisfiable(extra_constraints=[count > 3]))
                # print(i,count)
            if state.regs.rip.args[0]==0x4007db:
                print('get')
                print(state.posix.dumps(0).strip(b'\n'))
                # exit()
    print("over")

    # data = state.memory.load(state.regs.rbp - 0x34, 1)
    # print(state.satisfiable(extra_constraints=[state.memory.load(state.regs.rbp-0x34,1)==2]))


    # while True:
    #     simgr.step()
    #     for state in simgr.stashes['active']:
    #         if state.regs.rip.args[0]==0x4007e1 and (i==3 or i==4):
    #             data = state.memory.load(state.regs.rbp-0x34,2)
    #                 # state.satisfiable(extra_constraints=[state.memory.load(state.regs.rbp-0x34,1)==2]):
    #             break
    #     i+=1
    #     if i>=15:
    #         break


p = angr.Project("/tmp/fuzz/example/concolic_verify")
s = p.factory.entry_state()
simgr = p.factory.simulation_manager(s)
res = simgr.explore(find=0x400799)
print(res)
simgr = p.factory.simulation_manager(res.found[0])
simgr.use_technique(angr.exploration_techniques.ManualMerge4Step(0x400799, wait_counter=10))
# res = simgr.explore(find=0x4007f4)

mystep(simgr)
# simgr.step()
# simgr.step()
# simgr.merge()
# # simgr.stashes['active'][0].merge(simgr.stashes['active'][2],merge_conditions=[simgr.stashes['active'][2].history.jump_guards])
# new_s = simgr.stashes['active'][1]
# print(new_s.mem[new_s.regs.rbp-0x34].long)
# simgr.step()
# simgr.step()
# simgr.merge()
# new_s = simgr.stashes['active'][2]
# print(new_s.mem[new_s.regs.rbp-0x34].long)




