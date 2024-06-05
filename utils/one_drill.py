import driller
import os
import logging
l = logging.getLogger("driller.driller")
l.setLevel(logging.DEBUG)
logging.getLogger('angr.exploration_techniques.tracer').setLevel(logging.DEBUG)
def one_drill(binary, input_path, fuzz_bitmap_path, input=''):
    # d = driller.Driller("/tmp/fuzz/example/dataflow_obf", b'1234', b'\xff'*65536, debug=True)

    if input:
        d = driller.Driller(binary, input, b'\xff' * 65536, debug=True)
    else:
        data = open(input_path, 'rb').read()
        print("d = driller.Driller('{}', {}, b'\\xff'*65536)".format(os.path.basename(binary), data))
        d = driller.Driller(binary, data, b'\xff'*65536, debug=True)
    # d = driller.Driller("/tmp/fuzz/example/dataflow_err", b'1234', b'\xff'*65536)
    print(d.drill())

binary = "/tmp/fuzz/example/cb-multios/build64/challenges/Square_Rabbit/Square_Rabbit"
# binary = "/tmp/fuzz/example/cgc/cqe_binaries_1/NRFIN_00027/NRFIN_00027_01"
# binary = "/tmp/fuzz/example/concolic_verify"
input_path = "/dev/shm/work/Loud_Square_Instant_Messaging_Protocol_LSIMP/sync/fuzzer-master/queue/id:000003,src:000000,op:havoc,rep:64"
fuzz_bitmap_path = "/tmp/fuzz/pre/bitmaps/fuzz_bitmap003512"
one_drill(binary, input_path, fuzz_bitmap_path, b"fuzz\n")