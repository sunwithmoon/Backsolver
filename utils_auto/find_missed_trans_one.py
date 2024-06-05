import sys
import os
import pickle
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),os.pardir)))
from utils.bitmap2cfg import bitmap2cfg_old, bitmap2cfg
import angr
from utils.filter_name import filter_func_name
from utils.printhex import recursive_hex_change
bitmap_path = '/dev/shm/work/{}/sync/fuzzer-master/fuzz_bitmap'
taint_path = "/tmp/fuzz/angr_taint_engine/pickle_data/{}2_filter.pk"
files = ['jhead']



dirs = os.listdir('/dev/shm/work/')
# for dir in os.listdir('/dev/shm/work3/'):
for dir in files:
    if dir not in dirs:
        dir += "_1"
    assert dir in dirs
    bitmap = open(bitmap_path.format(dir), 'rb').read()
    name = dir
    if dir.endswith("_1"):
        dir = dir[:-2]

    print(dir)
    file_path = '/tmp/fuzz/example/jhead-master/{}'.format(name)
    file_size = os.path.getsize(file_path)
    # if file_size > 100 * 1024:
    #     continue
    meet, missed = bitmap2cfg(file_path, bitmap)
    # p = angr.Project(file_path, load_options={'auto_load_libs': False})
    # cfg = p.analyses.CFGFast()

    meet_addrs = set()
    for key in meet:
        meet_addrs.update(meet[key])
    not_meet_ifv = {}

    important_branches = set()
    missed_branch = set(map(lambda x: x[0], missed))
    taint_ifv = pickle.load(open(taint_path.format(name), 'rb'))
    for ifv in taint_ifv:
        target = [ifv]
        # filter_func_name(cfg, target, ["receive", "transmit", "recv", "send"])
        if not target:
            continue
        if taint_ifv[ifv] & missed_branch:
            important_branches |= set([hex(x) for x in taint_ifv[ifv] & missed_branch])
        if taint_ifv[ifv] - meet_addrs:
            not_meet_ifv[ifv] = set([hex(x) for x in taint_ifv[ifv] - meet_addrs])

    print("missed:")
    print((important_branches))


    print("not trigger:")
    print(not_meet_ifv)




