import os
import time
import signal
import hashlib
import resource
import pickle
import logging
import binascii
import pickle
import sys
import angr
import tracer
from functools import reduce
from driller import config
import argparse






class InitBitmap(object):
    """
    Driller object, symbolically follows an input looking for new state transitions.
    """

    def __init__(self, binary, input_str=b'fuzz', fuzz_bitmap=None, tag=None, redis=None, hooks=None, argv=None, fuzz_filename=None, debug=False, bitmap_path=None):
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
        self.bitmap_path = bitmap_path
        self.tag         = tag
        self.redis       = redis

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

        # Set the memory limit specified in the config.
        if config.MEM_LIMIT is not None:
            resource.setrlimit(resource.RLIMIT_AS, (config.MEM_LIMIT, config.MEM_LIMIT))

        # l.debug("[%s] drilling started on %s.", self.identifier, time.ctime(self.start_time))

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
        # for obj in p.loader.all_elf_objects:
        #     print(obj)

        exclude_range=[]
        for key in p.loader.shared_objects:
            if key==os.path.basename(self.binary):
                continue
            lib = p.loader.shared_objects[key]
            exclude_range.append((lib.mapped_base, lib.max_addr))


        include_range = []
        binary = p.loader.shared_objects[os.path.basename(self.binary)]
        include_range.append((binary.mapped_base, binary.max_addr))


        for addr, proc in self._hooks.items():
            p.hook(addr, proc)
            l.debug("Hooking %#x -> %s...", addr, proc.display_name)


        if p.loader.main_object.os == 'cgc':
            p.simos.syscall_library.update(angr.SIM_LIBRARIES['cgcabi_tracer'])
            s = p.factory.entry_state(stdin=angr.SimFileStream, flag_page=r.magic, mode='tracing')
        else:
            if self.fuzz_file:
                self.argv += [self.fuzz_file]
            s = p.factory.full_init_state(stdin=angr.SimFileStream, mode='tracing',args=self.argv, env=os.environ, add_options=angr.options.refs | {angr.options.TRACK_OP_ACTIONS})
            # s = p.factory.full_init_state(stdin=angr.SimFileStream, mode='tracing', args=self.argv, env=os.environ)
        if self.fuzz_filename:
            self.sim_file = angr.storage.file.SimFile(self.fuzz_file, writable=True, seekable=True, size=len(self.input))
            self.sim_file.set_state(s)
            s.fs.insert(self.fuzz_file, self.sim_file)
            s.preconstrainer.preconstrain_file(self.input, self.sim_file, True)
        else:
            s.preconstrainer.preconstrain_file(self.input, s.posix.stdin, True)

        simgr = p.factory.simulation_manager(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)

        t = angr.exploration_techniques.Tracer(trace=r.trace, crash_addr=r.crash_addr, copy_states=True, includes=include_range, fast_forward_to_entry=False)

        simgr.use_technique(t)
        for obj in p.loader.all_elf_objects:
            if not obj.is_main_bin:
                continue
            slide = t._aslr_slides[obj]
            max_addr = obj.max_addr
            min_addr = obj.min_addr
            break

        idx = 0
        count = 0
        prev = 0
        bitmap = [0xff]*65536


        # while simgr.active:
        while idx < len(r.trace):
            if r.trace[idx] < min_addr or r.trace[idx] > max_addr:
                idx += 1
                continue
            if not prev:
                prev = r.trace[idx]
                idx += 1
                continue
            cur = r.trace[idx]

            prev = (prev >> 4) ^ (prev << 8)
            prev &= 65535
            prev = prev >> 1

            cur = (cur >> 4) ^ (cur << 8)
            cur &= 65535

            bitmap[cur ^ prev] = 0
            prev = r.trace[idx]
            idx += 1


        return  bytes(bitmap)




### EXPLORER

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


            for op in angr.options.refs:
                try:
                    state.options.remove(op)
                except KeyError:
                    pass


            for op in angr.options.unicorn:
                try:
                    state.options.remove(op)
                except KeyError:
                    pass

        if iiv_solver:
            for event_type, bp in iiv_solver.bp_list:
                state.inspect.remove_breakpoint(event_type, bp)
        simgr = p.factory.simulation_manager(state, hierarchy=False)

        l.debug("[%s] started symbolic exploration at %s.", self.identifier, time.ctime())

        while len(simgr.active) and accumulated < 1024:
            l.debug("IP in generated try:%r",simgr.one_active.regs.ip)
            if simgr.one_active.addr==0x456ac5:
                state = simgr.one_active
                data = state.memory.load(state.regs.rbp-0x60,4)
                print("hit 7d1: {}".format(data))
                print(state.satisfiable(extra_constraints=[data!=0x31313233]))
                print(state.solver.eval(data, cast_to=bytes))
                print('')
            simgr.step()
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

    def _writeout(self, prev_addr, state):
        if self.fuzz_file:
            sim_file = state.fs._files[b'/home/user/'+self.fuzz_file.encode()]
            generated = sim_file.concretize()
        else:
            generated = state.posix.stdin.load(0, state.posix.stdin.pos)
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

'''
afl-showmap -m none -o out -Q -- /tmp/fuzz/example/cb-multios2/cb-multios/build64/challenges/Palindrome/Palindrome < crashes/id\:000001\,sig\:11\,src\:000000\,op\:havoc\,rep\:64 out.png
'''
if __name__ == "__main__":
    binary_path, input_path, bitmap_path = sys.argv[1:4]
    with open(input_path, "rb") as fp:
        input_str = fp.read()
    ib = InitBitmap(binary_path, input_str, bitmap_path=bitmap_path)
    bitmap = ib._drill_input()