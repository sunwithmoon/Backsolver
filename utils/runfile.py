import subprocess
import os
import signal
root = "/tmp/fuzz/example/cb-multios/build64/challenges"
rm = []
for dir in os.listdir(root):
    print(dir, end=': ')
    file = os.path.join(root, dir, dir)
    if not os.path.exists(file):
        file += '_1'
    proc = subprocess.Popen(file, shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err=proc.communicate(timeout=0.3)
    except subprocess.TimeoutExpired:
        out = b''
        err = b''
    print(out)

    proc.terminate()
    # if proc.returncode == -signal.SIGSEGV:
    #     rm.append(dir)
    #     os.system("mv {} /tmp/fuzz/example/cb-multios/build64/unexecutable/".format(os.path.join(root, dir)))

print(rm)
print(len(rm))