import angr
import argparse

def easy_traverse(node, bitmap, meet=[]):
    prev = node.addr
    meet.append(prev)
    prev = (prev >> 4) ^ (prev << 8)
    prev &= 65535
    prev = prev >> 1
    for succ_node in node.successors:
        cur = succ_node.addr
        if cur in meet:
            continue
        cur = (cur >> 4) ^ (cur << 8)
        cur &= 65535
        if bitmap[cur ^ prev] != 0xff:
            print(hex(node.addr), '->', succ_node.addr)
            easy_traverse(succ_node, bitmap, meet)

def complete_traverse(node, bitmap, meet=[]):
    prev = node.addr
    meet.append(prev)
    prev = (prev >> 4) ^ (prev << 8)
    prev &= 65535
    prev = prev >> 1
    for succ_node in node.successors:
        cur = succ_node.addr
        if cur in meet:
            continue
        cur = (cur >> 4) ^ (cur << 8)
        cur &= 65535
        if bitmap[cur ^ prev] != 0xff:
            print(hex(node.addr), '->', hex(succ_node.addr))
        complete_traverse(succ_node, bitmap, meet)



parser = argparse.ArgumentParser(description="parse bitmap")
parser.add_argument('binary')
parser.add_argument('bitmap')
args = parser.parse_args()
p = angr.Project(args.binary, auto_load_libs=False)
cfg = p.analyses.CFGFast()
bitmap = open(args.bitmap, 'rb').read()
node = cfg.get_any_node(p.entry)
complete_traverse(node, bitmap)