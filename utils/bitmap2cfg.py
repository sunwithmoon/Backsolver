import angr
import os
import subprocess
import binascii
from collections.abc import Iterable
import pickle


import logging
l = logging.getLogger("driller.driller")
l.setLevel(logging.DEBUG)

def cvt2hex(list):
    return [hex(i) if type(i)==int else cvt2hex(i) for i in list]
def print_hex(list):
    # print(list)
    print(cvt2hex(list))

def crc(prev, cur):
    prev = (prev >> 4) ^ (prev << 8)
    prev &= 65535
    prev = prev >> 1
    cur = (cur >> 4) ^ (cur << 8)
    cur &= 65535
    return cur ^ prev

def filter_fake_edge(meeted_crc, meet):
    for key in filter(lambda a: len(meeted_crc[a]) > 1, meeted_crc):
        target = list(meeted_crc[key])
        removes = []
        for i in range(len(target)):
            func_addr, pred, next, grandsun = target[i]
            if not grandsun:
                continue
            has_followers = False
            for follower in grandsun:
                if follower in meet[func_addr]:
                    has_followers = True
                    break
            if not has_followers:
                removes.append(target[i])
                if next in meet[func_addr]:
                    meet[func_addr].remove(next)
        for remove in removes:
            meeted_crc[key].remove(remove)

def is_nop_block(proj, block_addr, size):
    offset = 0
    for ins in proj.factory.block(block_addr).capstone.insns:
        if ins.mnemonic == 'nop':
            offset += ins.size
        else:
            return False
        if offset >= size:
            break
    return True

def bfs(proj, func_cfg, bitmap, func_meet, missed, start_node, partial):
    queue = [(0, start_node)]
    nop_block_info = {}
    visit = set()
    while queue:
        parent, node = queue.pop(0)
        if node in visit:
            continue
        visit.add(node)
        node_succ = func_cfg.succ[node]
        if not node_succ:
            # function return
            continue
        # check if is a nop block, skip it
        if len(node_succ) == 1 and is_nop_block(proj, node.addr, node.size):
            child_node = list(node_succ)[0]
            queue.append((node, child_node))
            nop_block_info[child_node.addr] = node.addr
            continue
        has_meet_branch = False
        meet_call = False # meet the block and the block has a call
        fake_return_target = None
        possible_missed = set()
        for child_node in node_succ:
            if partial is None or crc(node.addr, child_node.addr) in partial:
                if node_succ[child_node]['type'] in ('transition', 'call'):
                        if bitmap[crc(node.addr, child_node.addr)] ^ 0xff or \
                                (node.addr in nop_block_info and bitmap[crc(nop_block_info[node.addr], child_node.addr)] ^ 0xff):
                            func_meet.add(node.addr)
                            if node_succ[child_node]['type'] == 'call':
                                # the block contain a call
                                meet_call = True
                            else:
                                func_meet.add(child_node.addr)
                            queue.append((node, child_node))
                            has_meet_branch = True
                        else:
                            possible_missed.add((node.addr, child_node.addr))
                if node_succ[child_node]['type'] == 'fake_return':
                    fake_return_target = child_node
                    queue.append((node, fake_return_target))
                    func_meet.add(fake_return_target.addr)

        if has_meet_branch:
            missed.update(possible_missed)
        else:


            # all children are missed, so this node must be missed
            # TODO: crc应该计算父亲节点
            if node.addr in func_meet:
                # exclude plt function
                func_meet.remove(node.addr)
                missed.add((parent.addr, node.addr))


        if meet_call and len(node_succ) > 1:
            # The met block contains a call
            # if len(node_succ) == 1, call without return, the callee is exit()
            assert  len(node_succ) == 2
            # queue.append((node, fake_return_target))
            # func_meet.add(fake_return_target.addr)



def bitmap2cfg(binary, bitmap, partial=None):
    '''
    bfs in function to get meeted transitions
    :param binary:
    :param bitmap:
    :param partial: a crc list, if not None, only get the transitions whose crc is in partial
    :return:
    '''
    meet = {}
    missed = set()
    proj_path = binary + '.proj.pk'
    if False: #os.path.exists(proj_path):
        with open(proj_path, 'rb') as f:
            p, cfg_funcs = pickle.load(f)
    else:
        p = angr.Project(binary, load_options={'auto_load_libs': False})
        cfg = p.analyses.CFGFast(resolve_indirect_jumps=True)
        # cfg = p.analyses.CFGEmulated(context_sensitivity_level=1, resolve_indirect_jumps=True)
        cfg_funcs = cfg.kb.functions
        # with open(proj_path, 'wb') as f:
        #     pickle.dump((p, cfg_funcs), f)
    for func_addr in cfg_funcs:
        if func_addr < p.loader.main_object.min_addr or func_addr > p.loader.main_object.max_addr:
            continue
        meet[func_addr] = set()
        func_cfg = cfg_funcs[func_addr].transition_graph
        for node in func_cfg.nodes:
            if func_cfg.in_degree(node) == 0:
                start_node = node
                if start_node.addr != func_addr:
                    continue
                break
        # print(hex(func_addr))
        bfs(p, func_cfg, bitmap, meet[func_addr], missed, start_node, partial)
    return meet, missed


def get_missed_ifv(binary, bitmap_path, ifvl_path, partial=None):
    bitmap = open(bitmap_path, 'rb').read()
    meet, missed = bitmap2cfg(binary, bitmap, partial)
    ifvl_filter_path = ifvl_path[:-3] + '_filter.pk'
    with open(ifvl_filter_path, 'rb') as f:
        ifvl_filter = pickle.load(f)
    with open(ifvl_path, 'rb') as f:
        tainted = set(pickle.load(f))
    ifv = set()
    for func_addr in ifvl_filter:
        ifv.update(ifvl_filter[func_addr])
    # print("tainted & ifv:", len(tainted & missed_ifv))
    missed = set(map(lambda x: x[0], missed))
    print("missed", len(missed))
    print(missed)
    missed_ifv = (ifv & missed) - tainted
    print("missed_ifv & missed but not tainted", len(missed_ifv), "%.1f%%"% (100*len(missed_ifv) / len(missed)))
    print(missed_ifv)
    missed_taint = (missed & tainted) - ifv
    print("missed_taint - ifv:", len(missed_taint), "%.1f%%"% (100*len(missed_taint) / len(missed)))
    missed_ifv_taint = missed & ifv & tainted
    print("missed_ifv & missed_taint:", len(missed_ifv_taint),  "%.1f%%"% (100*len(missed_ifv_taint) / len(missed)))
    other = missed - ifv - tainted
    print("other missed:", len(other), "%.1f%%"% (100*len(other) / len(missed)))
    # print(sorted([hex(a) for a in meet]))




if __name__ == '__main__':
    bitmap_path = '/dev/shm/work_backsolver/Tennis_Ball_Motion_Calculator/sync/fuzzer-master/fuzz_bitmap'
    binary = '/tmp/fuzz/example/cb-multios/build64/challenges/Tennis_Ball_Motion_Calculator/Tennis_Ball_Motion_Calculator'

    bitmap_path = '/dev/shm/work_backsolver/branch_merge2/sync/fuzzer-master/fuzz_bitmap'
    binary = '/tmp/fuzz/example/MyTestSuite/branch_merge2'
    bitmap_path = '/dev/shm/work3/jhead/sync/fuzzer-master/fuzz_bitmap'
    # bitmap_path = '/dev/shm/work_backsolver/jhead/sync/fuzzer-master/fuzz_bitmap'
    binary = "/tmp/fuzz/example/nanosvg/build/example2"
    bitmap_path = '/dev/shm/work/example2/sync/fuzzer-master/fuzz_bitmap'

    binary = "/tmp/fuzz/example/libpng-1.6.36/pngimage"
    ifvl = "/tmp/fuzz/angr_taint_engine/pickle_data/pngimage.pk"
    bitmap_path = '/tmp/fuzz/log/work_symqemu/pngimage/287/bitmap'
    # bitmap_path = '/tmp/fuzz/log/work_fuzzolic/pngimage/287/bitmap'
    # bitmap_path = "/dev/shm/work_backsolver/pngimage/sync/fuzzer-master/fuzz_bitmap"
    bitmap_path = '/tmp/fuzz/log/work_qsym/pngimage/287/bitmap'
    # bitmap_path = '/tmp/fuzz/log/work/pngimage/286/bitmap'
    # bitmap_path = '/dev/shm/work_qsym/pngimage/sync/fuzzer-master/fuzz_bitmap'

    # binary = "/tmp/fuzz/example/plutosvg/build/example/plutosvg"
    # ifvl = "/tmp/fuzz/angr_taint_engine/pickle_data/plutosvg.pk"
    # bitmap_path = '/tmp/fuzz/log/work_symqemu/plutosvg/287/bitmap'
    # bitmap_path = '/tmp/fuzz/log/work_qsym/plutosvg/287/bitmap'
    # bitmap_path = '/tmp/fuzz/log/work/plutosvg/286/bitmap'
    # bitmap_path = '/tmp/fuzz/log/work_fuzzolic/plutosvg/287/bitmap'
    #
    #
    binary = "/tmp/fuzz/example/jhead-master/jhead"
    ifvl = "/tmp/fuzz/angr_taint_engine/pickle_data/jhead3.pk"
    bitmap_path = '/tmp/fuzz/log/work_symqemu/jhead/287/bitmap'
    bitmap_path = '/tmp/fuzz/log/work_qsym/jhead/265/bitmap'
    bitmap_path = '/tmp/fuzz/log/work/jhead/191/bitmap'
    # bitmap_path = '/tmp/fuzz/log/work_fuzzolic/jhead/287/bitmap'

    # binary = "/tmp/fuzz/example/MyTestSuite/branch_merge2"
    # bitmap_path = '/tmp/fuzz/log/work_fuzzolic/branch_merge2/00/bitmap'
    #
    # binary = "/tmp/fuzz/example/file/src/file"
    # ifvl = "/tmp/fuzz/angr_taint_engine/pickle_data/file.pk"
    # bitmap_path = '/tmp/fuzz/log/work_fuzzolic/file/287/bitmap'
    # bitmap_path = '/tmp/fuzz/log/work_symqemu/file/270/bitmap'
    # bitmap_path = '/tmp/fuzz/log/work_qsym/file/287/bitmap'
    binary = "/tmp/fuzz/example/MyTestSuite/src/loop1"
    bitmap_path = "/dev/shm/work_backsolver/loop1/sync/fuzzer-master/fuzz_bitmap"
    ifvl = "/tmp/fuzz/angr_taint_engine/pickle_data/loop1.pk"

    # binary = "/tmp/fuzz/example/MyTestSuite/src/branch2"
    # bitmap_path = "/dev/shm/work_backsolver/branch2/sync/fuzzer-master/fuzz_bitmap"
    # ifvl = "/tmp/fuzz/angr_taint_engine/pickle_data/branch2.pk"

    binary = "/tmp/fuzz/example/MyTestSuite/src/mix"
    bitmap_path = "/dev/shm/work_backsolver/mix/sync/fuzzer-master/fuzz_bitmap"
    ifvl = "/tmp/fuzz/angr_taint_engine/pickle_data/mix.pk"

    binary = "/tmp/fuzz/example/MyTestSuite/src/loop2"
    bitmap_path = "/dev/shm/work_backsolver/loop2/sync/fuzzer-master/fuzz_bitmap"
    ifvl = "/tmp/fuzz/angr_taint_engine/pickle_data/loop2.pk"

    # get_missed_ifv(binary, bitmap_path, ifvl)
    # exit()


    DEBUG = False
    bitmap = open(bitmap_path, 'rb').read()
    # partial = {1024, 19460, 58414, 64559, 16436, 35392, 38465, 44098, 44610, 48195, 50244, 51268, 54341, 55877, 56389, 58950, 58438, 60998, 21069, 22093, 39505, 40017, 40529, 56413, 57950, 59998, 34912, 35424, 61535, 63583, 32888, 44154, 34624, 50500, 640, 12419, 64199, 34504, 50396, 23773, 32992, 35040, 53989, 36600, 768, 41746, 58670, 64303, 65327, 35136, 37697, 42818, 44866, 49476, 39233, 52036, 44354, 48451, 65351, 62791, 53060, 53573, 21325, 21837, 22349, 39761, 44538, 64343, 64855, 49500, 55645, 58718, 61791, 35680, 62815, 38777, 44410, 65455, 4561, 24541, 60894, 61919, 58334, 5097, 43514}
    if DEBUG:
        partial = None
        meet, missed = bitmap2cfg_old(binary, bitmap, partial)
        # print(meet)
    else:
        partial = None
        meet, missed = bitmap2cfg(binary, bitmap, partial)

    print(meet)
    print(sum(map(lambda a: len(meet[a]), meet)))
    # print(set(map(lambda x:(hex(x[0]),hex(x[1])), missed)))



