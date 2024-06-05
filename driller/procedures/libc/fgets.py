import angr
import claripy
from cle.backends.externs.simdata.io_file import io_file_data_for_arch

######################################
# fread
######################################

class fgets(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst, size, file_ptr):
        # TODO handle errors

        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fd = self.state.mem[file_ptr + fd_offset:].int.resolved
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return -1
        if size.symbolic:
            try:
                nm_min = self.state.solver.min(size)
                nm_max = self.state.solver.max(size)
                if nm_min == nm_max:
                    self.state.add_constraints(size == nm_min)
                    # self.state.add_constraints(nm <= nm_min + 10)
            except:
                pass
        ret = simfd.read(dst, size)

        self.state.memory.store(file_ptr, self.state.memory.load(file_ptr,8).get_byte(0) | claripy.BVV(0x10, 8))
            # self.state.add_constraints(flag.get_byte(0) & 0x10)
        return self.state.solver.If(size == 0, 0, ret)


