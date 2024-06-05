import angr
class TracerError(Exception):
    pass

class TracerConvert:
    def __init__(self, binary):
        self.project = angr.Project(binary)


    def _filter_idx(self, angr_addr, idx):
        return True
        # change to log ins
        slide = self._trace[idx] - angr_addr
        block = self.project.factory.block(angr_addr)
        legal_next = block.vex.constant_jump_targets
        if legal_next:
            return any(a + slide == self._trace[idx + 1] for a in legal_next)
        else:
            # the intuition is that if the first block of an initializer does an indirect jump,
            # it's probably a call out to another binary (notably __libc_start_main)
            # this is an awful fucking heuristic but it's as good as we've got
            return abs(self._trace[idx] - self._trace[idx + 1]) > 0x1000

    def _locate_entry_point(self, angr_addr):
        # ...via heuristics
        indices = set()
        threshold = 0x40000
        while not indices and threshold > 0x2000:
            for idx, addr in enumerate(self._trace):
                if ((addr - angr_addr) & 0xfff) == 0 and (idx == 0 or abs(self._trace[idx-1] - addr) > threshold):
                    indices.add(idx)

            indices = set(i for i in indices if self._filter_idx(angr_addr, i))
            threshold //= 2
        return indices

    def _translate_state_addr(self, state_addr, obj=None):
        if obj is None:
            obj = self.project.loader.find_object_containing(state_addr)
        if obj not in self._aslr_slides:
            raise Exception("Internal error: cannot translate address")
        return state_addr + self._aslr_slides[obj]

    def _translate_trace_addr(self, trace_addr, obj=None):
        # might be wrong
        if obj is None:
            for obj in self._aslr_slides:  # pylint: disable=redefined-argument-from-local
                if obj.contains_addr(trace_addr - self._aslr_slides[obj]):
                    break
            else:
                raise Exception("Can't figure out which object this address belongs to")
        if obj not in self._aslr_slides:
            raise Exception("Internal error: object is untranslated")
        return trace_addr - self._aslr_slides[obj]

    def _compare_addr(self, trace_addr, state_addr):
        if self._current_slide is not None and trace_addr == state_addr + self._current_slide:
            return True

        current_bin = self.project.loader.find_object_containing(state_addr)
        if current_bin is self.project.loader._extern_object or current_bin is self.project.loader._kernel_object:
            return False
        elif current_bin in self._aslr_slides:
            self._current_slide = self._aslr_slides[current_bin]
            return trace_addr == state_addr + self._current_slide
        elif ((trace_addr - state_addr) & 0xfff) == 0:
            self._aslr_slides[current_bin] = self._current_slide = trace_addr - state_addr
            return True
        # error handling
        elif current_bin:
            raise TracerError("Trace desynced on jumping into %s. Did you load the right version of this library?" % current_bin.provides)
        else:
            raise TracerError("Trace desynced on jumping into %#x, where no library is mapped!" % state_addr)


    def _identify_aslr_slides(self):
        """
        libraries can be mapped differently in the original run(in the trace) and in angr
        this function identifies the difference(called aslr slides) of each library to help angr translate
        original address and address in angr back and forth
        """
        if self._aslr:
            # if we don't know whether there is any slide, we need to identify the slides via heuristics
            for obj in self.project.loader.all_elf_objects:
                # heuristic 1: non-PIC  objects are loaded without aslr slides
                if not obj.pic:
                    self._aslr_slides[obj] = 0
                    continue

                # heuristic 2: library objects with custom_base_addr are loaded at the correct locations
                if obj._custom_base_addr:
                    l.info("%s is assumed to be loaded at the address matching the one in the trace", obj)
                    self._aslr_slides[obj] = 0
                    continue

                # heuristic 3: entry point of an object should appear in the trace
                possibilities = None
                for entry in obj.initializers + ([obj.entry] if obj.is_main_bin else []):
                    indices = self._locate_entry_point(entry)
                    slides = {self._trace[idx] - entry for idx in indices}
                    if possibilities is None:
                        possibilities = slides
                    else:
                        if slides:
                            possibilities.intersection_update(slides)

                if possibilities is None:
                    continue

                if len(possibilities) == 0:
                    raise TracerError(
                        "Trace does not seem to contain object initializers for %s. Do you want to have a Tracer(aslr=False)?" % obj)
                if len(possibilities) == 1:
                    self._aslr_slides[obj] = next(iter(possibilities))
                else:
                    if obj.is_main_bin:
                        # maybe need to change if bug happens
                        possibilities = [x for x in possibilities if hex(x + entry).startswith('0x4000')]
                        if len(possibilities) == 1:
                            self._aslr_slides[obj] = possibilities[0]
                            continue
                    raise TracerError(
                        "Trace seems ambiguous with respect to what the ASLR slides are for %s. This is surmountable, please open an issue." % obj)
        else:
            # if we know there is no slides, just trust the address in the loader
            for obj in self.project.loader.all_elf_objects:
                self._aslr_slides[obj] = 0
            self._current_slide = 0

    def init_run(self, trace):
        # trace = r.trace, crash_addr = r.crash_addr
        self._trace = trace
        self._aslr = True
        self._aslr_slides = {}  # type: Dict[cle.Backend, int]
        self._identify_aslr_slides()
        # self._crash_addr = crash_addr