import pickle
import os
print(os.path.abspath('.'))
fp = open('../trace.pk', 'rb')
trace = pickle.load(fp)
print(type(trace))
fp = open('../trace_seg.txt', 'w')
passed_addr = []
for addr in set(trace):
    if trace.count(addr) >= 2:
        passed_addr.append(addr)


old = 0
for addr in trace:
    if addr in passed_addr:
        old = addr
        continue
    if abs(old - addr) > 0x100000:
        fp.write('\n')
    old = addr
    fp.write(hex(addr) + ' ')
fp.close()