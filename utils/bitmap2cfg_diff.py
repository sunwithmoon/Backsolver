from bitmap2cfg import bitmap2cfg
from functools import reduce

binary = "/tmp/fuzz/example/jhead-master/jhead"
bitmap_path1 = '/dev/shm/work/jhead/sync/fuzzer-master/fuzz_bitmap'
# bitmap_path1 = '/tmp/fuzz/log/work/jhead/188/bitmap'
bitmap_path2 = '/tmp/fuzz/log/work_symqemu/jhead/286/bitmap'

# binary = "/tmp/fuzz/example/libjpeg-turbo/build/cjpeg-static"
# bitmap_path1 = '/dev/shm/work/cjpeg-static/sync/fuzzer-master/fuzz_bitmap'
# bitmap_path2 = '/dev/shm/work_backsolver/cjpeg-static/sync/fuzzer-master/fuzz_bitmap'
bitmap1 = open(bitmap_path1, 'rb').read()
bitmap2 = open(bitmap_path2, 'rb').read()
meet1, missed = bitmap2cfg(binary, bitmap1)
meet2, missed = bitmap2cfg(binary, bitmap2)

meet1_addrs = set(reduce(lambda x,y:x | y, map(lambda a: meet1[a], meet1), set()))
meet2_addrs = set(reduce(lambda x,y:x | y, map(lambda a: meet2[a], meet2), set()))
print("path1 uniq:")
print([hex(x) for x in meet1_addrs - meet2_addrs])
print()
print("path2 uniq:")
print([hex(x) for x in meet2_addrs - meet1_addrs])