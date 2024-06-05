import os
root = '/dev/shm/work'
crashes = []
src = '/tmp/fuzz/example/cb-multios/challenges'
dst = '/tmp/fuzz/example/cb-multios2/cb-multios/challenges'
for dir in os.listdir(root):
    if dir.startswith('.') or dir == 'test':
        continue
    crash_dir = os.path.join(root, dir, 'sync', 'fuzzer-master', 'crashes')
    if os.listdir(crash_dir):
        crashes.append(dir)
        cmd = f'cp -r {src}/{dir} {dst}/{dir}'
        os.system(cmd)

print(crashes)