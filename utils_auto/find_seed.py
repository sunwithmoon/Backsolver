import sys
import os
import pickle
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),os.pardir)))
import tracer
import binascii
import subprocess
from utils.tracer_convert import TracerConvert

cmd_fmt = "/tmp/pin/pin -t /tmp/pin/source/tools/ManualExamples/obj-intel64/inscount0.so --"
def get_trace_addrs(trace, tracecvt):
    addrs = []
    for addr in trace:
        try:
            state_addr = tracecvt._translate_trace_addr(addr)
        except:
            continue
        if state_addr >= tracecvt.project.loader.main_object.min_addr and state_addr <= tracecvt.project.loader.main_object.max_addr:
            addrs.append(hex(state_addr))
    return addrs

def find_seed2addr(binary, seed_dir, addrs, exclude=None,qemu_argv=None, log_path="/tmp/pin/res/a.log",target=None, meet_one=None):

    """
    Find a seed that can reach a specific address.
    :param binary: Path to the binary.
    :param seed_dir: Path to the seed directory.
    :param qemu_argv: A list of arguments to pass to QEMU.
    :return: A tuple (seed, addr), or None if no seed can reach the address.
    """
    if qemu_argv is None:
        qemu_argv = [os.path.basename(binary)]
    if exclude is None:
        exclude = []

    res = []
    seed_crc = set()
    tracecvt = TracerConvert(binary)
    if target is None:
        target = os.listdir(seed_dir)
    for file in target:
        # if '185' not in file:
        #     continue
        print(file)

        seed_path = os.path.join(seed_dir, file)
        if os.path.isfile(seed_path) == False:
            continue
        if not check_seed_size(seed_path):
            continue
        fp = open(seed_path, 'rb')
        seed = fp.read()
        fp.close()
        crc = binascii.crc32(seed) & 0xffffffff
        if crc in seed_crc:
            continue
        seed_crc.add(crc)
        cmd = cmd_fmt.split(' ')
        if qemu_argv[-1] == '@':
            cmd += qemu_argv[:-1] + [seed_path]
            cmd += [log_path]
        else:
            cmd += qemu_argv + ['<', seed_path, '>', log_path]



        # print(cmd_fmt.split(' ') + qemu_argv + [log_path])
        proc = subprocess.Popen(cmd, shell=False, stdin=subprocess.PIPE , stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        try:
            out, err = proc.communicate()
        except subprocess.TimeoutExpired:
            pass
        proc.terminate()
        trace = []
        fpr =  open(log_path, 'rb')
        for line in fpr:
            trace.append(int(line.strip(), 16))
        fpr.close()


        # r = tracer.qemu_runner.QEMURunner(binary, seed, argv=qemu_argv)
        tracecvt.init_run(trace)
        if meet_one is None:
            trace_addrs = [tracecvt._translate_state_addr(addr) for addr in addrs]
            passed = False
            for trace_addr in trace_addrs:
                if trace_addr not in trace:
                    passed = True
                    break
            exclude_addrs = [tracecvt._translate_state_addr(addr) for addr in exclude]
            for exclude_addr in exclude_addrs:
                if exclude_addr in trace:
                    passed = True
                    break

            if not passed:
                res.append(file)
                print('found:',file)
                print(get_trace_addrs(trace, tracecvt))
                break
        else:
            trace_addrs = set(tracecvt._translate_state_addr(addr) for addr in meet_one)
            if len(trace_addrs & set(trace)) > 0:
                res.append(file)
                print('found:',file,[hex(x) for x in trace_addrs & set(trace)])
                # print("trace:")
                # trace_addrs = get_trace_addrs(trace, tracecvt)
                break



    print(res)


def check_seed_size(seed_path):
    fp = open(seed_path, 'rb')
    seed = fp.read()
    fp.close()
    if len(seed) >= 100:
        return True
    return False


os.environ['QEMU_LD_PREFIX'] = "/tmp/.virtualenvs/driller/bin/afl-unix/../fuzzer-libs/x86_64"
binary = "/tmp/fuzz/example/MyTestSuite/src/branch2"
seed_dir = "/dev/shm/work_backsolver/branch2/sync/fuzzer-master/queue"
# seed_dir = "/dev/shm/work_backsolver/branch2/sync/driller/queue"

binary = "/tmp/fuzz/example/MyTestSuite/src/loop2"
seed_dir = "/dev/shm/work_backsolver/loop2/sync/fuzzer-master/queue"

# binary = "/tmp/fuzz/example/libjpeg-turbo/build/cjpeg-static"
# seed_dir = "/dev/shm/work_backsolver/cjpeg-static/sync/fuzzer-master/queue"
# binary = '/tmp/fuzz/example/cb-multios/build64/challenges/Tennis_Ball_Motion_Calculator/Tennis_Ball_Motion_Calculator'
# seed_dir = "/dev/shm/work_backsolver/Tennis_Ball_Motion_Calculator/sync/fuzzer-master/queue"
# binary = '/tmp/fuzz/example/MyTestSuite/branch_merge2'
# seed_dir = "/dev/shm/work_backsolver/branch_merge2/sync/fuzzer-master/queue"
addr = 0x408EAD
# addr = 0x408EE5
addrs = [addr]
addrs = [0x401736] #, 0x404226]
# meet_one = [0x408000, 0x409005, 0x40800d, 0x40a013, 0x408013, 0x408020, 0x408026, 0x40882b, 0x403830, 0x408033, 0x408835, 0x408039, 0x40a040, 0x403840, 0x408842, 0x409840, 0x408046, 0x40384a, 0x40884c, 0x40984d, 0x407850, 0x408053, 0x40a053, 0x403858, 0x40805d, 0x700060, 0x40a060, 0x408861, 0x409867, 0x40a06c, 0x408870, 0x407874, 0x409875, 0x40a078, 0x40787e, 0x40a084, 0x409888, 0x700090, 0x408090, 0x40a090, 0x407890, 0x408890, 0x409890, 0x408896, 0x40889b, 0x4080a1, 0x40a0a3, 0x4098a6, 0x4088a9, 0x7000b0, 0x4080b0, 0x40a0b0, 0x4078b0, 0x40a8b0, 0x4088b5, 0x4078b8, 0x40a0bc, 0x4098bc, 0x4080c1, 0x40a0c1, 0x4078ce, 0x7000d0, 0x4080d0, 0x40a0d4, 0x4078d4, 0x4088d5, 0x4098d5, 0x40a0d9, 0x4088da, 0x4098df, 0x4088e4, 0x40a8e5, 0x4080e6, 0x40a0ec, 0x7000f0, 0x40a0f1, 0x40a8f5, 0x4078f8, 0x4080f9, 0x4088f9, 0x408903, 0x40a104, 0x408109, 0x40a109, 0x408912, 0x408113, 0x40b118, 0x40a11c, 0x40811d, 0x40b11d, 0x40891c, 0x700120, 0x40a121, 0x40791f, 0x40a922, 0x407924, 0x40a134, 0x40b138, 0x40a139, 0x407938, 0x40a944, 0x407946, 0x40b14a, 0x40a14c, 0x40b14f, 0x407950, 0x40a151, 0x408956, 0x408158, 0x40b158, 0x40a958, 0x700160, 0x408960, 0x40a960, 0x40a164, 0x407965, 0x408169, 0x40a169, 0x40b16b, 0x40896f, 0x408170, 0x407970, 0x40a971, 0x408979, 0x40817a, 0x40a17c, 0x40a97c, 0x407980, 0x40a181, 0x40b181, 0x407987, 0x408989, 0x40a98a, 0x700190, 0x408190, 0x40a194, 0x408994, 0x40a996, 0x40a199, 0x40819c, 0x40899e, 0x4079a2, 0x4081a3, 0x4081a8, 0x40a1ac, 0x4089ad, 0x7001b0, 0x40a1b1, 0x4079b0, 0x4089b7, 0x4081bb, 0x40a9bb, 0x4079be, 0x40a9c1, 0x40a1c4, 0x4079c8, 0x40a1c9, 0x4089cc, 0x7001d0, 0x4081d3, 0x4089d6, 0x4081dc, 0x40a1dc, 0x4079dd, 0x40a1e1, 0x4081e5, 0x4079e8, 0x4081ee, 0x4099f0, 0x40a1f4, 0x4079f5, 0x40a1f9, 0x4081fa, 0x4099fc, 0x408204, 0x408a05, 0x407a0a, 0x409a0a, 0x40a20c, 0x408210, 0x40a211, 0x407a10, 0x40aa10, 0x408a13, 0x40821d, 0x408a1d, 0x409a1d, 0x40aa1e, 0x407a20, 0x408223, 0x40a224, 0x407a27, 0x40aa28, 0x40a229, 0x408a2c, 0x409a2c, 0x408230, 0x409a35, 0x408236, 0x408a38, 0x409a3a, 0x40a23c, 0x407a3f, 0x408243, 0x40aa46, 0x407a48, 0x409a4d, 0x40aa4f, 0x408250, 0x40a250, 0x408a50, 0x409a57, 0x408a58, 0x40aa58, 0x40825e, 0x409a60, 0x408a61, 0x407a64, 0x408268, 0x408a6c, 0x409a6c, 0x407a70, 0x409a78, 0x408a7c, 0x408280, 0x408a81, 0x40aa83, 0x408288, 0x409a8e, 0x408a90, 0x409a98, 0x408a99, 0x40829b, 0x40aa9b, 0x408a9e, 0x4082a0, 0x407aa0, 0x40aaa0, 0x409aab, 0x407aad, 0x4082af, 0x40aaaf, 0x408ab0, 0x40aab0, 0x4082b5, 0x40aab7, 0x409aba, 0x407ac0, 0x409ac0, 0x407ac4, 0x408ac4, 0x409ac9, 0x4082ce, 0x409acf, 0x407ad0, 0x40aacf, 0x408ad4, 0x409ad8, 0x40aadf, 0x407ae0, 0x4082e4, 0x409ae4, 0x407aef, 0x4082f0, 0x407af6, 0x40aaf6, 0x408af9, 0x4082fd, 0x408303, 0x407b08, 0x408b0a, 0x407b0d, 0x408310, 0x408b10, 0x408316, 0x408b1a, 0x407b20, 0x408323, 0x407b25, 0x408b2f, 0x408330, 0x407b30, 0x407b38, 0x40833a, 0x404b40, 0x407b41, 0x408b44, 0x408b52, 0x408b5c, 0x407b60, 0x408370, 0x407b70, 0x408b79, 0x40837d, 0x407b7f, 0x408b7f, 0x409b80, 0x408383, 0x407b86, 0x408b8c, 0x409b8c, 0x408390, 0x407b90, 0x407b95, 0x408b96, 0x409b98, 0x40839d, 0x409ba4, 0x4083a7, 0x407ba8, 0x409bb0, 0x408bb4, 0x407bb8, 0x4083c0, 0x408bc0, 0x407bc6, 0x4083c9, 0x409bca, 0x407bd0, 0x408bd0, 0x408bd5, 0x4083e0, 0x409be4, 0x408bf0, 0x4043f4, 0x4083fc, 0x408bfc, 0x408401, 0x408c01, 0x408416, 0x407c1d, 0x408420, 0x408c24, 0x408c29, 0x40842d, 0x402430, 0x40843a, 0x408c3d, 0x409c40, 0x408c45, 0x408447, 0x409c5a, 0x408c5c, 0x402c5f, 0x409c60, 0x408467, 0x408470, 0x408c79, 0x409c7a, 0x40847d, 0x408483, 0x408c87, 0x409c88, 0x408c8c, 0x402490, 0x408490, 0x409c92, 0x40849a, 0x408ca4, 0x408ca9, 0x4084b0, 0x4084be, 0x408cc1, 0x408cc6, 0x4084ca, 0x4024d0, 0x4084d0, 0x408cd6, 0x408cdb, 0x4084df, 0x409ce0, 0x40ace0, 0x407ce5, 0x4084ed, 0x408cf0, 0x40acf0, 0x407cf3, 0x408cf5, 0x40acf8, 0x409cfa, 0x408cff, 0x408500, 0x408508, 0x40ad09, 0x402510, 0x40ad10, 0x407d14, 0x408515, 0x408522, 0x40ad26, 0x40852f, 0x40ad2f, 0x408538, 0x40ad39, 0x408542, 0x407d48, 0x40854a, 0x402550, 0x406d51, 0x407d64, 0x408569, 0x408570, 0x40ad77, 0x40857b, 0x407d7c, 0x40ad83, 0x408585, 0x407d87, 0x407d90, 0x408591, 0x407d9b, 0x409da0, 0x4085a6, 0x40ada8, 0x4025b0, 0x4085b0, 0x406db1, 0x407db6, 0x4085ba, 0x409dba, 0x40adbd, 0x407dbe, 0x4045c0, 0x4085c3, 0x407dcc, 0x4045ce, 0x4085ce, 0x4085d7, 0x407dd7, 0x4085d9, 0x4085e0, 0x407deb, 0x4085f0, 0x406df0, 0x407df1, 0x4085f7, 0x40ae00, 0x407e01, 0x408603, 0x402e06, 0x408610, 0x409e10, 0x407e14, 0x409e19, 0x407e1c, 0x409e1f, 0x408628, 0x407e29, 0x409e2b, 0x407e2f, 0x402630, 0x408630, 0x40ae35, 0x409e37, 0x40ae3a, 0x407e3c, 0x409e40, 0x407e49, 0x40864b, 0x409e4c, 0x408650, 0x407e56, 0x407e5c, 0x40865f, 0x408669, 0x407e69, 0x40866e, 0x407e6f, 0x40867b, 0x407e7c, 0x407e89, 0x40868c, 0x402690, 0x408692, 0x407e96, 0x40869c, 0x407ea2, 0x4086a9, 0x407eae, 0x4096c4, 0x4096c8, 0x4086ca, 0x4026d0, 0x409ed0, 0x4096db, 0x407ee0, 0x409ee3, 0x4096e9, 0x407eec, 0x409ef0, 0x4086f6, 0x407ef7, 0x409efc, 0x409700, 0x408703, 0x407f07, 0x408f07, 0x409f08, 0x402710, 0x408711, 0x407f10, 0x409713, 0x409f14, 0x40871b, 0x407f1f, 0x409720, 0x408738, 0x407f3a, 0x40873e, 0x407f44, 0x407f4a, 0x40874b, 0x409756, 0x407f57, 0x408758, 0x407f60, 0x407f65, 0x408766, 0x40876e, 0x407f78, 0x40877f, 0x408788, 0x407f88, 0x407f90, 0x408798, 0x40879d, 0x407fa0, 0x408fa0, 0x4087a7, 0x407fac, 0x408fb4, 0x4087b6, 0x4077c0, 0x4087c0, 0x407fc1, 0x409fc8, 0x4087cd, 0x407fd1, 0x4077d8, 0x409fdb, 0x4037e0, 0x409fe0, 0x407fe2, 0x4037ec]
# meet_one = list(filter(lambda x: not hex(x).startswith('0x402'), meet_one))
# meet_one = [0x401ED3]
meet_one = None
exclude = []
# error_addrs = [0x405C64, 0x405D80, 0x405DB0]
# exclude = error_addrs
# target=["id:000028,src:000000,op:arith8,pos:3,val:-6,+cov"]
target = None
cmd = "{} @".format(binary)
# cmd = binary + " @"
find_seed2addr(binary, seed_dir, addrs, exclude=exclude, qemu_argv=cmd.split(),target=target, meet_one=meet_one)
