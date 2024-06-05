def get_blocks(proj, cfg):
    blocks = set()
    for func_addr in cfg.kb.functions:
        if func_addr >= proj.loader.main_object.min_addr and func_addr <= proj.loader.main_object.max_addr:
            blocks |= cfg.kb.functions[func_addr].block_addrs_set
    return blocks
