import logging

from angr.procedures.stubs.format_parser import FormatParser

from cle.backends.externs.simdata.io_file import io_file_data_for_arch

l = logging.getLogger(name=__name__)

######################################
# fprintf
######################################

class __fprintf_chk(FormatParser):

    def run(self, file_ptr, size):
        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fileno = self.state.mem[file_ptr + fd_offset:].int.resolved
        simfd = self.state.posix.get_fd(fileno)
        if simfd is None:
            return -1

        # The format str is at index 1
        fmt_str = self._parse(2)
        out_str = fmt_str.replace(3, self.arg)

        simfd.write_data(out_str, out_str.size() // 8)

        return out_str.size() // 8
