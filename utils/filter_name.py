def get_func_name(cfg, addr):
    if type(addr) == str:
        addr = int(addr, 16)
    func_addr = cfg.functions.floor_func(addr).addr
    func = cfg.kb.functions[func_addr]
    return func.name

def filter_func_name(cfg, data, filter_list=["receive", "transmit"]):
    rm_list = []
    for addr in data:
        addr_int = int(addr, 16)
        func_name = get_func_name(cfg, addr_int)
        for filter_name in filter_list:
            if filter_name in func_name:
                rm_list.append(addr)
    for addr in rm_list:
        if type(data) == dict:
            data.pop(addr)
        else:
            data.remove(addr)