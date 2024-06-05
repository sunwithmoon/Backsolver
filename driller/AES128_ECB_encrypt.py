import angr
import claripy


class AES128_ECB_encrypt(angr.SimProcedure):
    #pylint:disable=arguments-differ,attribute-defined-outside-init,redefined-outer-name

    def run(self, input, key, out):
        data = claripy.BVV(0, 16*8)
        self.state.memory.store(out, data)



