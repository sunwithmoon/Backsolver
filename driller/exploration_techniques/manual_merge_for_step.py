import logging

from angr.exploration_techniques import ExplorationTechnique

l = logging.getLogger(name=__name__)
logging.getLogger("angr.state_plugins.preconstrainer").setLevel(logging.CRITICAL)
class ManualMerge4Step(ExplorationTechnique):
    def __init__(self, address, wait_counter=10, merge_threshold=2):
        '''

        :param address: merge address list
        :param wait_counter: the max wait state number, if hit then merge states
        :param merge_threshold: the min state number to merge
        '''
        super(ManualMerge4Step, self).__init__()
        self.address_list = address if type(address)==list else [address]
        self.wait_counter_limit = wait_counter
        self.wait_counter = 0
        self.last_stash = ""
        self.address = 0
        self.merge_threshold = merge_threshold
        self.merge_wait = {}
        '''
        {
            merge_waiting_addr: {
                1: [states], # merge_count: [states]
                2: [states],
                ...
            }
        }
        '''
        for address in self.address_list:
            self.merge_wait[address] = {}




    def get_merge_constraints(self, group):
        '''
        get constrains of a group of states to merge
        :param group:   a group of states
        :return:        constraints
        '''
        constraints = []
        for state in group:
            state_constraints = []
            cur = state.history
            meet = -1

            # get constraints before last merging
            while cur and meet:
                # in the first meeting, it reaches where states should be merged,
                # in the second meeting, it reaches last merged constraints
                if cur.addr == self.address:
                    meet += 1
                state_constraints.extend(cur.recent_constraints)
                cur = cur.parent


            constraints.append(state_constraints)
        # TODO: I use a fucking way to remove the same constraints
        min_len = min(map(lambda x: len(x), constraints))
        for i in range(min_len):
            if len(set(map(lambda x:str(x[-1]), constraints))) == 1:
                for c in constraints:
                    c.pop(-1)
            else:
                break
        return constraints







    def step(self, simgr, stash='active', **kwargs):


        # we need to force stop at the merge address
        extra_stop_points = set(kwargs.pop("extra_stop_points", []))
        extra_stop_points.update(set(self.address_list))

        # perform all our analysis as a post-mortem on a given step
        simgr = simgr.step(stash=stash, extra_stop_points=extra_stop_points, **kwargs)
        #self.mark_okfilter(simgr, stash)

        for state in list(simgr.stashes[stash]):
            if state.addr in self.address_list:
                self.address = state.addr
                state.globals['merge_count'] = state.globals.get('merge_count', 0) + 1
                if state.globals['merge_count'] not in self.merge_wait[state.addr]:
                    self.merge_wait[state.addr][state.globals['merge_count']] = []
                self.merge_wait[state.addr][state.globals['merge_count']].append(state)
                simgr.stashes[stash].remove(state)


        # tick the counter
        self.wait_counter += 1

        # see if it's time to merge (out of active or hit the wait limit)
        if len(simgr.stashes[stash]) != 0 and self.wait_counter < self.wait_counter_limit:
            return simgr

        #self.mark_nofilter(simgr, self.stash)

        # do the merge, keyed by unique callstack
        for addr in self.merge_wait:
            for count in self.merge_wait[addr]:
                if len(self.merge_wait[addr][count]) >= self.merge_threshold or len(simgr.stashes[stash]) == 0:
                    simgr.stashes['merge_tmp'] = self.merge_wait[addr][count]
                    if len(self.merge_wait[addr][count]) > 1:
                        l.info("Merging %d states at %#x", len(self.merge_wait[addr][count]), addr)
                        o = simgr.merge_tmp[0]
                        try:
                            constraints = self.get_merge_constraints(simgr.merge_tmp)
                            m, _, _ = o.merge(*simgr.merge_tmp[1:], merge_conditions=constraints)
                        except Exception as e:
                            print(e)
                        while simgr.merge_tmp:
                            simgr.merge_tmp.pop()
                        simgr.merge_tmp.append(m)
                    simgr = simgr.move('merge_tmp', stash)



        return simgr
