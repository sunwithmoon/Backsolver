import os
import struct
root = "/dev/shm/work/jhead/sync/fuzzer-master/queue"
for file in os.listdir(root):
    path = os.path.join(root, file)
    if not os.path.isfile(path):
        continue
    data = open(path, 'rb').read()
    if len(data) < 0x14:
        continue
    magic, length, con_str = struct.unpack(">4sh10s", data[:0x10])
    # print(magic, length, con_str)
    if magic[:3] == b"\xff\xd8\xff"  and con_str == b"\x45\x78\x69\x66\x00\x00\x4d\x4d\x00\x2a":
        print(file)