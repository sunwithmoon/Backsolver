import angr
import driller
# d = driller.Driller('simple_test',b'fuzztest',b'\xff'*65536)
# for new_input in d.drill_generator():
#     print(new_input)
p = angr.Project('simple_test', load_options={'auto_load_libs':False})
state = p.factory.entry_state()
simgr = p.factory.simgr(state)
while simgr.active:
    simgr.step()
    print(simgr.active)
    for s in simgr.active:
        if s.addr==0x4007ad:
            print(s.solver.constraints)
            print(s.posix.dumps(0))
            exit()
s = simgr.found[0]
