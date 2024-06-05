import driller

binary = "/tmp/fuzz/example/jhead-master/jhead"
d=driller.Driller(binary,b"\xff"*16,b"\xff"*65536,fuzz_filename="test")
new_inputs = d.drill()