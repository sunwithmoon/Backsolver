import sys
import os
import pickle
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),os.pardir)))
import tracer
import binascii
import subprocess
from utils.tracer_convert import TracerConvert

cmd_fmt = "/tmp/pin/pin -t /tmp/pin/source/tools/ManualExamples/obj-intel64/inscount0.so --"
def crc_trans(prev, cur):
    prev = (prev >> 4) ^ (prev << 8)
    prev &= 65535
    prev = prev >> 1

    cur = (cur >> 4) ^ (cur << 8)
    cur &= 65535
    return cur ^ prev
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

def find_seed2addr(binary, seed_dir, path, qemu_argv=None, target = None,log_path="/tmp/pin/res/a.log"):

    """
    Find a seed that can reach a specific address.
    :param binary: Path to the binary.
    :param seed_dir: Path to the seed directory.
    :param qemu_argv: A list of arguments to pass to QEMU.
    :return: A tuple (seed, addr), or None if no seed can reach the address.
    """
    if qemu_argv is None:
        qemu_argv = [os.path.basename(binary)]

    res = []
    seed_crc = set()
    fp = open(path, 'r')
    blocks = eval(fp.read())
    max_addr = max(blocks)
    min_addr = min(blocks)

    tracecvt = TracerConvert(binary)
    if target is None:
        target = os.listdir(seed_dir)[::-1]
    for file in target:
        # if '185' not in file:
        #     continue


        seed_path = os.path.join(seed_dir, file)
        if os.path.isfile(seed_path) == False:
            continue

        fp = open(seed_path, 'rb')
        seed = fp.read()
        fp.close()
        print(file)
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

        max_trace = tracecvt._translate_state_addr(max_addr)
        min_trace = tracecvt._translate_state_addr(min_addr)
        trace_state = []
        prev = 0
        for trace_addr in trace:
            if trace_addr < min_trace or trace_addr > max_trace:
                continue
            cur = tracecvt._translate_trace_addr(trace_addr)
            trace_state.append(crc_trans(prev, cur))
            prev = cur
        crc = binascii.crc32(str(trace_state).encode()) & 0xffffffff
        if crc not in seed_crc:
            seed_crc.add(crc)
            print(hex(crc))
        # print([hex(x) for x in trace_state])

    print('end')
    print(len(seed_crc))


def check_seed_size(seed_path):
    fp = open(seed_path, 'rb')
    seed = fp.read()
    fp.close()
    if len(seed) >= 100:
        return True
    return False


os.environ['QEMU_LD_PREFIX'] = "/tmp/.virtualenvs/driller/bin/afl-unix/../fuzzer-libs/x86_64"
binary = "/tmp/fuzz/example/jhead-master/jhead"
seed_dir = "/dev/shm/work_backsolver/jhead/sync/driller/queue"

# cmd = "{} -mkexif -di -dx -purejpg -cs o1 -zt -ft -autorot -norot -exifmap -cr -ca -ar -dt -v @".format(binary)
cmd = binary + " -v @"
path = "/tmp/fuzz/example/jhead-master/blocks.txt"
target = ["id:000010,from:fuzzer-master000011", "id:046906,from:fuzzer-master000811"]
target = None
find_seed2addr(binary, seed_dir, path, qemu_argv=cmd.split(), target=target)
