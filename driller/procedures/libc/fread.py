import angr
import claripy
from cle.backends.externs.simdata.io_file import io_file_data_for_arch

######################################
# fread
######################################

class fread(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst, size, nm, file_ptr):
        # TODO handle errors

        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fd = self.state.mem[file_ptr + fd_offset:].int.resolved
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return -1
        if nm.symbolic:
            try:
                nm_min = self.state.solver.min(nm)
                nm_max = self.state.solver.max(nm)
                if nm_min == nm_max:
                    self.state.add_constraints(nm == nm_min)
                    # self.state.add_constraints(nm <= nm_min + 10)
            except:
                pass
        ret = simfd.read(dst, size * nm)
        if not self.state.solver.satisfiable(extra_constraints=((simfd._pos if isinstance(simfd._pos, claripy.ast.bv.BV) else simfd._pos.ast) != simfd.file._size,)):
            self.state.memory.store(file_ptr, self.state.memory.load(file_ptr,8).get_byte(0) | claripy.BVV(0x10, 8))
            # self.state.add_constraints(flag.get_byte(0) & 0x10)
        return self.state.solver.If(self.state.solver.Or(size == 0, nm == 0), 0, ret // size)

fread_unlocked = fread
