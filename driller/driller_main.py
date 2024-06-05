import os
import sys
# sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),os.pardir)))
import time
import signal
import hashlib
import resource
import pickle
import logging
import binascii
import pickle

import angr
import tracer
from func_timeout import func_timeout, FunctionTimedOut, func_set_timeout
from functools import reduce
from . import config
from .utils import get_blocks


l = logging.getLogger("driller.driller")
l.setLevel(logging.DEBUG)
logging.getLogger('driller.exploration_techniques.iiv_solver').setLevel(logging.DEBUG)
logging.getLogger('driller.exploration_techniques.tracer').setLevel(logging.DEBUG)
l_drillercore = logging.getLogger('preconstraint_process')
l_drillercore.setLevel(logging.DEBUG)
logging.getLogger("driller.exploration_techniques.manual_merge_for_step").setLevel(logging.DEBUG)



class Driller(object):
    """
    Driller object, symbolically follows an input looking for new state transitions.
    """

    def __init__(self, binary, input_str, fuzz_bitmap=None, tag=None, redis=None, hooks=None, argv=None, fuzz_filename=None, debug=False, ifvls='', continuous_solve=False):
        """
        :param binary     : The binary to be traced.
        :param input_str  : Input string to feed to the binary.
        :param fuzz_bitmap: AFL's bitmap of state transitions (defaults to empty).
        :param redis      : redis.Redis instance for coordinating multiple Driller instances.
        :param hooks      : Dictionary of addresses to simprocedures.
        :param argv       : Optionally specify argv params (i,e,: ['./calc', 'parm1']),
                            defaults to binary name with no params.
        """

        self.binary      = binary

        # Redis channel identifier.
        self.identifier  = os.path.basename(binary)
        self.input       = input_str
        self.fuzz_bitmap = fuzz_bitmap
        self.tag         = tag
        self.redis       = redis

        self.ifvls       = ifvls
        self.debug       = debug
        self.debug_path  = "/tmp/fuzz/pre/debug/"
        self.debug_simgr = self.debug_path + "simgr1.pkl"
        self.argv = argv or [binary]
        self.fuzz_filename   = fuzz_filename
        self.qemu_argv   = [c for c in self.argv]
        if fuzz_filename:
            self.qemu_argv += [fuzz_filename]

        self.sim_file    = None
        self.fuzz_file   = os.path.basename(fuzz_filename) if fuzz_filename else None
        # self.argv[0] = os.path.basename(self.argv[0])

        self.base = os.path.join(os.path.dirname(__file__), "..")

        # The simprocedures.
        self._hooks = {} if hooks is None else hooks

        # The driller core, which is now an exploration technique in angr.
        self._core = None

        # Start time, set by drill method.
        self.start_time = time.time()

        # Set of all the generated inputs.
        self._generated = set()
        self.continuous_solve = continuous_solve

        # Set the memory limit specified in the config.
        if config.MEM_LIMIT is not None:
            resource.setrlimit(resource.RLIMIT_AS, (config.MEM_LIMIT, config.MEM_LIMIT))

        l.debug("[%s] drilling started on %s.", self.identifier, time.ctime(self.start_time))

### DRILLING

    def drill(self):
        """
        Perform the drilling, finding more code coverage based off our existing input base.
        """

        # Don't re-trace the same input.
        if self.redis and self.redis.sismember(self.identifier + '-traced', self.input):
            return -1

        # Write out debug info if desired.
        if l.level == logging.DEBUG and config.DEBUG_DIR:
            self._write_debug_info()
        elif l.level == logging.DEBUG and not config.DEBUG_DIR:
            l.warning("Debug directory is not set. Will not log fuzzing bitmap.")

        # Update traced.
        if self.redis:
            self.redis.sadd(self.identifier + '-traced', self.input)

        list(self._drill_input())

        if self.redis:
            return len(self._generated)
        else:
            return self._generated

    def drill_generator(self):
        """
        A generator interface to the actual drilling.
        """

        # Set up alarm for timeouts.
        if config.DRILL_TIMEOUT is not None:
            signal.alarm(config.DRILL_TIMEOUT)

        for i in self._drill_input():
            yield i

    def _drill_input(self):
        """
        Symbolically step down a path with a tracer, trying to concretize inputs for unencountered
        state transitions.
        """


        r = tracer.qemu_runner.QEMURunner(self.binary, self.input, argv=self.qemu_argv)
        p = angr.Project(self.binary)
        p_no_lib = angr.Project(self.binary, load_options={'auto_load_libs': False})
        cfg_nolib = p_no_lib.analyses.CFGFast()
        blocks = get_blocks(p, cfg_nolib)

        exclude_range=[]
        main_bin = p.loader.shared_objects[os.path.basename(self.binary)]
        for key in p.loader.shared_objects:
            lib = p.loader.shared_objects[key]
            print(lib)
            if key==os.path.basename(self.binary):
                continue

            exclude_range.append((lib.mapped_base, lib.max_addr))


        include_range = []
        binary = p.loader.shared_objects[os.path.basename(self.binary)]
        include_range.append((binary.mapped_base, binary.max_addr))

        from procedures.procedure_dict import hook_funcs
        l.debug("-----------find target library functions-------------")
        for func_name in hook_funcs:
            if func_name in p.loader.main_object.plt:
                l.debug("find %s", func_name)
                p.hook_symbol(func_name, hook_funcs[func_name](), replace=True)

        for addr, proc in self._hooks.items():
            p.hook(addr, proc)
            l.debug("Hooking %#x -> %s...", addr, proc.display_name)


        from driller.AES128_ECB_encrypt import AES128_ECB_encrypt
        p.hook_symbol('AES128_ECB_encrypt', AES128_ECB_encrypt(), replace=True)
        if p.loader.main_object.os == 'cgc':
            p.simos.syscall_library.update(angr.SIM_LIBRARIES['cgcabi_tracer'])

            s = p.factory.entry_state(stdin=angr.SimFileStream, flag_page=r.magic, mode='tracing')
        else:
            if self.fuzz_file:
                self.argv += [self.fuzz_file]
            s = p.factory.full_init_state(stdin=angr.SimFileStream, mode='tracing',args=self.argv, env=os.environ, add_options=angr.options.refs | {angr.options.TRACK_OP_ACTIONS})

        if self.fuzz_filename:
            self.sim_file = angr.storage.file.SimFile(self.fuzz_file, writable=True, seekable=True, size=len(self.input))
            self.sim_file.set_state(s)
            s.fs.insert(self.fuzz_file, self.sim_file)
            s.preconstrainer.preconstrain_file(self.input, self.sim_file, True)
        else:
            s.preconstrainer.preconstrain_file(self.input, s.posix.stdin, True)

        simgr = p.factory.simulation_manager(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)
        from .exploration_techniques import Tracer
        t = Tracer(trace=r.trace, crash_addr=r.crash_addr, copy_states=True, includes=include_range,
                                               # mode="permissive",
                                              fast_forward_to_entry=False
                                               )


        from .exploration_techniques import DrillerCore, IIVSolver, UnicornStop

        if self.ifvls:
            t.project = p
            t._identify_aslr_slides()
            data_path = self.ifvls
            data = pickle.load(open(data_path, "rb"))
            # remove the branches that are not affected by ifv
            for branch in list(data):
                try:
                    if not any(map(lambda x: t._translate_state_addr(x, obj=main_bin) in r.trace, data[branch]['influent_branch'])):
                        del data[branch]
                except Exception as e:
                    import traceback
                    traceback.print_exc()
                    print(e, "branch: %x"%(branch))
                    exit()

            iiv_solver = IIVSolver(p, data, continuous_solve=self.continuous_solve)
            self._core = DrillerCore(trace=r.trace, fuzz_bitmap=self.fuzz_bitmap,
                                                             optimistic_solving=True, iiv_solver=iiv_solver, cfg=cfg_nolib)

            stop_addr = set()
            save_addr = set()
            for loop_entry in data:
                for addr in data[loop_entry]['backtrack_addr']:
                    stop_addr.add(addr)
                    save_addr.add(addr)
                for ins_addr, block_addr, _, _ in data[loop_entry]['write_ins']:
                    # if write_addr is start of a block
                    if ins_addr != block_addr:
                        stop_addr.add(ins_addr)
            simgr.use_technique(UnicornStop(stop_addr, save_addr, iiv_solver.snapshots))
        else:
            self._core = DrillerCore(trace=r.trace, fuzz_bitmap=self.fuzz_bitmap, cfg=cfg_nolib
                                                                 # optimistic_solving=True
                                                                 )
            iiv_solver = None

        simgr.use_technique(t)
        simgr.use_technique(angr.exploration_techniques.Oppologist())
        simgr.use_technique(self._core)

        if self.ifvls:
            simgr.use_technique(iiv_solver)

        self._set_concretizations(simgr.one_active)

        l.debug("---***+++***---")
        l.debug("Drilling into %r.", self.input)
        l.debug("Input is %r.", self.input)


        count = 0
        while simgr.active and simgr.one_active.globals['trace_idx'] < len(r.trace) - 1:
            simgr.step()
            if self.debug:
                l.debug("IP:%r", [hex(s.regs.ip.args[0]) for s in simgr.stashes["active"]])


            # Check here to see if a crash has been found.
            if self.redis and self.redis.sismember(self.identifier + '-finished', True):
                return

            if 'diverted' not in simgr.stashes:
                continue

            while simgr.diverted:
                state = simgr.diverted.pop(0)
                in_lib = False
                for min_addr, max_addr in exclude_range:
                    if state.addr >= min_addr and state.addr <= max_addr:
                        in_lib = True
                        break
                if in_lib:
                    continue
                l.debug("Found a diverted state, exploring to some extent.")
                try:
                    w = self._writeout(state.history.bbl_addrs[-1], state)
                except FunctionTimedOut:
                    continue
                if w is not None:
                    yield w
                try:
                    for i in self._symbolic_explorer_stub(state, iiv_solver=iiv_solver):
                        yield i
                except FunctionTimedOut:
                    pass

### EXPLORER
    @func_set_timeout(10)
    def _symbolic_explorer_stub(self, state, iiv_solver=None):
        # Create a new simulation manager and step it forward up to 1024
        # accumulated active states or steps.
        steps = 0
        accumulated = 1

        p = state.project
        state = state.copy()
        try:
            state.options.remove(angr.options.LAZY_SOLVES)
        except KeyError:
            pass


            # for op in angr.options.refs:
            #     try:
            #         state.options.remove(op)
            #     except KeyError:
            #         pass
            #
            #
            # for op in angr.options.unicorn:
            #     try:
            #         state.options.remove(op)
            #     except KeyError:
            #         pass

        if iiv_solver:
            for event_type, bp in iiv_solver.bp_list:
                state.inspect.remove_breakpoint(event_type, bp)
        simgr = p.factory.simulation_manager(state, hierarchy=False)

        l.debug("[%s] started symbolic exploration at %s.", self.identifier, time.ctime())

        while len(simgr.active) and accumulated < 100:
            try:
                simgr.step()
            except:
                break
            steps += 1

            # Dump all inputs.
            accumulated = steps * (len(simgr.active) + len(simgr.deadended))

        l.debug("[%s] stopped symbolic exploration at %s.", self.identifier, time.ctime())

        # DO NOT think this is the same as using only the deadended stashes. this merges deadended and active
        simgr.stash(from_stash='deadended', to_stash='active')
        for dumpable in simgr.active:
            try:
                if dumpable.satisfiable():
                    w = self._writeout(dumpable.history.bbl_addrs[-1], dumpable)
                    if w is not None:
                        yield w

            # If the state we're trying to dump wasn't actually satisfiable.
            except IndexError:
                pass
            except FunctionTimedOut:
                pass

### UTILS

    @staticmethod
    def _set_concretizations(state):
        if state.project.loader.main_object.os == 'cgc':
            flag_vars = set()
            for b in state.cgc.flag_bytes:
                flag_vars.update(b.variables)

            state.unicorn.always_concretize.update(flag_vars)

        # Let's put conservative thresholds for now.
        state.unicorn.concretization_threshold_memory = 50000
        state.unicorn.concretization_threshold_registers = 50000

    def _in_catalogue(self, length, prev_addr, next_addr):
        """
        Check if a generated input has already been generated earlier during the run or by another
        thread.

        :param length   : Length of the input.
        :param prev_addr: The source address in the state transition.
        :param next_addr: The destination address in the state transition.

        :return: boolean describing whether or not the input generated is redundant.
        """

        key = '%x,%x,%x\n' % (length, prev_addr, next_addr)

        if self.redis:
            return self.redis.sismember(self.identifier + '-catalogue', key)

        # No redis means no coordination, so no catalogue.
        else:
            return False

    def _add_to_catalogue(self, length, prev_addr, next_addr):
        if self.redis:
            key = '%x,%x,%x\n' % (length, prev_addr, next_addr)
            self.redis.sadd(self.identifier + '-catalogue', key)
        # No redis = no catalogue.

    #
    # @func_set_timeout(2)
    def _writeout(self, prev_addr, state):
        if self.fuzz_file:
            sim_file = state.fs._files[b'/home/user/'+self.fuzz_file.encode()]
            generated = sim_file.concretize()
        else:
            generated = state.posix.stdin.load(0, len(self.input))
            generated = state.solver.eval(generated, cast_to=bytes)

        key = (len(generated), prev_addr, state.addr)

        # Checks here to see if the generation is worth writing to disk.
        # If we generate too many inputs which are not really different we'll seriously slow down AFL.
        if self._in_catalogue(*key):
            self._core.encounters.remove((prev_addr, state.addr))
            return None

        else:
            self._add_to_catalogue(*key)

        l.debug("[%s] dumping input for %#x -> %#x.", self.identifier, prev_addr, state.addr)

        self._generated.add((key, generated))

        if self.redis:
            # Publish it out in real-time so that inputs get there immediately.
            channel = self.identifier + '-generated'

            self.redis.publish(channel, pickle.dumps({'meta': key, 'data': generated, "tag": self.tag}))

        else:
            l.debug("Generated: %s", binascii.hexlify(generated)) 

        return (key, generated)

    def _write_debug_info(self):
        m = hashlib.md5()
        m.update(self.input)
        f_name = os.path.join(config.DEBUG_DIR, self.identifier + '_' + m.hexdigest() + '.py')

        with open(f_name, 'w+') as f:
            l.debug("Debug log written to %s.", f_name)
            f.write("binary = %r\n" % self.binary
                    + "started = '%s'\n" % time.ctime(self.start_time)
                    + "input = %r\n" % self.input
                    + "fuzz_bitmap = %r" % self.fuzz_bitmap)

