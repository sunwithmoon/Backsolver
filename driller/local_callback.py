import os
import sys
import signal
import logging.config
import driller
import argparse
import subprocess
import multiprocessing
import time
import binascii

l = logging.getLogger("driller.local_callback")

def _run_drill(drill, fuzz, _path_to_input_to_drill, debug=False, length_extension=None, ifvls='', argv=None, continuous_solve=False):
    '''

    :param drill:
    :param fuzz:
    :param _path_to_input_to_drill:
    :param length_extension:
    :param argv:  string
    :return:
    '''
    _binary_path = fuzz.binary_path
    _fuzzer_out_dir = fuzz.out_dir
    _bitmap_path = os.path.join(_fuzzer_out_dir, 'fuzzer-master', "fuzz_bitmap")
    _timeout = drill._worker_timeout
    l.warning("starting drilling of %s, %s", os.path.basename(_binary_path), os.path.basename(_path_to_input_to_drill))
    args = (
        "timeout", "-k", str(_timeout+10), str(_timeout),
        sys.executable, os.path.abspath(__file__),
        _binary_path, _fuzzer_out_dir, _bitmap_path, _path_to_input_to_drill
    )
    if debug:
        args += ('--debug',)
    if continuous_solve:
        args += ('--continuous_solve',)
    if length_extension:
        args += ('--length-extension', str(length_extension))
    if ifvls:
        args += ('--ifvls', ifvls)
    if argv:
        args += ('--argv', argv)


    if 'QEMU_LD_PREFIX' in os.environ:
        print("QEMU_LD_PREFIX = {}".format(os.environ['QEMU_LD_PREFIX']))
        fp=open('/dev/shm/work/driller_out.log','w')
        fp.write('[driller cmd] '+' '.join(args))
        fp.close()
    else:
        print("no QEMU_LD_PREFIX")
    # os.environ['QEMU_LD_PREFIX'] = ""


    # os.system(' '.join(args))
    p = subprocess.Popen(args)
    print(p.communicate())



class LocalCallback(object):
    def __init__(self, num_workers=1, worker_timeout=30*60, debug=True,length_extension=None, ifvls='', argv=None, continuous_solve=False):
        self._already_drilled_inputs = set()
        self._num_workers = num_workers
        self._running_workers = []
        self._worker_timeout = worker_timeout
        self.debug = debug
        self._length_extension = length_extension
        self.argv = argv
        self.ifvls = ifvls
        self.continuous_solve = continuous_solve

    @staticmethod
    def _queue_files(fuzz, fuzzer='fuzzer-master'):
        '''
        retrieve the current queue of inputs from a fuzzer
        :return: a list of strings which represent a fuzzer's queue
        '''

        queue_path = os.path.join(fuzz.out_dir, fuzzer, 'queue')
        queue_files = filter(lambda x: x != ".state", os.listdir(queue_path))
        queue_files = [os.path.join(queue_path, q) for q in queue_files]

        return queue_files

    def driller_callback(self, fuzz):
        l.warning("Driller stuck callback triggered!")
        # remove any workers that aren't running
        self._running_workers = [x for x in self._running_workers if x.is_alive()]

        # get the files in queue
        queue = self._queue_files(fuzz)
        #for i in range(1, fuzz.fuzz_id):
        #    fname = "fuzzer-%d" % i
        #    queue.extend(self.queue_files(fname))

        # start drilling
        not_drilled = set(queue) - self._already_drilled_inputs
        # print("queue: ",len(queue))
        # # l.log("_already_drilled_inputs: %r", self._already_drilled_inputs)
        # print("not_drilled: ", len(not_drilled))
        if len(not_drilled) == 0:
            l.warning("no inputs left to drill")

        while len(self._running_workers) < self._num_workers and len(not_drilled) > 0:
            to_drill_path = list(not_drilled)[0]
            not_drilled.remove(to_drill_path)
            self._already_drilled_inputs.add(to_drill_path)
            print("input from", to_drill_path)
            if 'QEMU_LD_PREFIX' in os.environ:
                print("before multiprocessing: QEMU_LD_PREFIX = {}".format(os.environ['QEMU_LD_PREFIX']))
                fp = open('/dev/shm/work/QEMU_LD_PREFIX.log', 'w')
                fp.write("QEMU_LD_PREFIX = {}".format(os.environ['QEMU_LD_PREFIX']))
                fp.close()
            else:
                print("no QEMU_LD_PREFIX")

            proc = multiprocessing.Process(target=
                                           _run_drill, args=(self, fuzz, to_drill_path),
                    kwargs={'debug': self.debug,
                            'length_extension': self._length_extension,
                            'ifvls': self.ifvls,
                            'argv':self.argv,
                            'continuous_solve': self.continuous_solve
                            })
            proc.start()
            self._running_workers.append(proc)
    __call__ = driller_callback

    def kill(self):
        for p in self._running_workers:
            try:
                p.terminate()
                os.kill(p.pid, signal.SIGKILL)
            except OSError:
                pass

# this is for running with bash timeout
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Driller local callback")
    parser.add_argument('binary_path')

    parser.add_argument('fuzzer_out_dir')
    parser.add_argument('bitmap_path')
    parser.add_argument('path_to_input_to_drill')
    parser.add_argument('--debug', action="store_true")
    parser.add_argument('--ifvls', default="")
    parser.add_argument('--length-extension', help="Try extending inputs to driller by this many bytes", type=int)
    parser.add_argument('--argv', default=None)
    parser.add_argument('--continuous_solve', action="store_true", help="Keep solve branches for iiv solving")
    # parser.add_argument('fuzz_filename', default=None, help="filename for fuzz")
    args = parser.parse_args()

    logcfg_file = os.path.join(os.getcwd(), '.driller.ini')
    if os.path.isfile(logcfg_file):
        logging.config.fileConfig(logcfg_file)

    binary_path, fuzzer_out_dir, bitmap_path, path_to_input_to_drill = sys.argv[1:5]

    fuzzer_bitmap = open(args.bitmap_path, "rb").read()

    # create a folder
    driller_dir = os.path.join(args.fuzzer_out_dir, "driller")
    driller_queue_dir = os.path.join(driller_dir, "queue")
    try: os.mkdir(driller_dir)
    except OSError: pass
    try: os.mkdir(driller_queue_dir)
    except OSError: pass

    l.debug('drilling %s', path_to_input_to_drill)
    # os.environ['QEMU_LD_PREFIX']="/tmp/.virtualenvs/driller/bin/afl-unix/../fuzzer-libs/i386"
    # l.debug("QEMU_LD_PREFIX = {}".format(os.environ['QEMU_LD_PREFIX']))
    # get the input
    input_bytes = open(args.path_to_input_to_drill, "rb").read()

    if args.length_extension:
        input_bytes += b'\x00' * args.length_extension
    inputs_to_drill = [input_bytes]

    if not args.debug:
        bitmap_path = "/tmp/fuzz/pre/bitmaps/"
        found_path = "/tmp/fuzz/pre/found/"
        index = len(os.listdir(bitmap_path))
        l.debug("generate input number file:found{:06d}.".format(index))
        fp = open(found_path + "found{:06d}".format(index), "w")
        start_time = time.time()
    crc_set = set()
    for input_to_drill in inputs_to_drill:
        if args.argv:
            argvs = args.argv.split(' ')
            for argv in list(argvs):
                if not argv:
                    argvs.remove(argv)

            d = driller.Driller(args.binary_path, input_to_drill, fuzzer_bitmap, ifvls=args.ifvls, argv=argvs, fuzz_filename=args.path_to_input_to_drill,debug=args.debug, continuous_solve=args.continuous_solve)
        else:
            d = driller.Driller(args.binary_path, input_to_drill, fuzzer_bitmap, ifvls=args.ifvls, debug=args.debug, continuous_solve=args.continuous_solve)
        count = 0
        for new_input in d.drill_generator():
            new_crc = binascii.crc32(new_input[1])
            if new_crc in crc_set:
                continue
            else:
                crc_set.add(new_crc)
            if not args.debug:
                id_num = len(os.listdir(driller_queue_dir))
                fuzzer_from = args.path_to_input_to_drill.split("sync/")[1].split("/")[0] + args.path_to_input_to_drill.split("id:")[1].split(",")[0]
                filepath = "id:" + ("%d" % id_num).rjust(6, "0") + ",from:" + fuzzer_from
                filepath = os.path.join(driller_queue_dir, filepath)
                with open(filepath, "wb") as f:
                    f.write(new_input[1])
            count += 1
        l.warning("found %d new inputs", count)
        if not args.debug:
            fp.write("found %d new inputs\n"% count)
    if not args.debug:
        end_time = time.time()
        fp.write("using time:{}s\n".format(end_time - start_time))
        fp.close()

