## Backsolver

Backsolver is utilized to address implicit flows in concolic execution.
It is based on Driller and needs the implicit flow variable information, which could be obtained by [Backsolver_taint](https://github.com/sunwithmoon/Backsolver_taint).

Example:
```shell
# python driller/local_callback.py binary work_dir fuzz_bitmap testcase --ifvls ifvls_path

python driller/local_callback.py
/MyTestSuite/src/loop2
/dev/shm/work/loop2
/dev/shm/work/loop2/sync/fuzzer-master/fuzz_bitmap
"/dev/shm/work/loop2/sync/fuzzer-master/queue/id:000208,src:000000,op:havoc,rep:128"
--debug
--argv "/MyTestSuite/src/loop2"
--ifvls /pickle_data/loop2_fin.pk
--length-extension 200
```

