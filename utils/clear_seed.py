from driller.init_bitmap import InitBitmap
import os
import subprocess
import binascii
import logging
l = logging.getLogger("driller.driller")
l.setLevel(logging.DEBUG)

def clear_seed(binary, dir):
    seeds = os.listdir(dir)
    meet_bitmap = set()
    meet_str = set()
    for seed in seeds:
        if seed == "hit_bitmap":
            continue
        print(seed)
        with open(os.path.join(dir, seed), "rb") as fp:
            input_str = fp.read()
        crc = binascii.crc32(input_str) & 0xffffffff
        if crc in meet_str:
            print('del')
            cmd = "rm {}".format(os.path.join(dir, seed)).split()
            print(cmd)
            p = subprocess.Popen(cmd)
            p.communicate()
            continue

        ib = InitBitmap(binary, input_str)
        bitmap = ib._drill_input()
        crc = binascii.crc32(bitmap) & 0xffffffff
        if crc not in meet_bitmap:
            meet_bitmap.add(crc)
        else:
            print('del')
            cmd = "rm {}".format(os.path.join(dir, seed)).split()
            print(cmd)
            p = subprocess.Popen(cmd)
            p.communicate()

'''
afl-cmin -i crashes/ -o crash_min -Q -- /tmp/fuzz/example/cb-multios2/cb-multios/build64/challenges/Palindrome/Palindrome
afl-tmin -i id\:000000\,sig\:11\,src\:000000\,op\:havoc\,rep\:64 -o id0_out -- /tmp/fuzz/example/cb-multios2/cb-multios/build64/challenges/Palindrome/Palindrome
'''
clear_seed('/tmp/fuzz/example/cb-multios/build64/challenges/Square_Rabbit/Square_Rabbit', '/dev/shm/work/Square_Rabbit/sync/driller/queue')


