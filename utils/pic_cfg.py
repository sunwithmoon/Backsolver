class ColoringBB():
    flowchart = False
    tgt_ea = 0
    startea = 0
    endea = 0
    addr_fc = 0

    def __init__(self, addr_fc):
        self._set_fc_address(addr_fc)
        self._set_flowchart()

    def _set_fc_address(self, addr_fc):
        self.addr_fc = addr_fc

    def _set_flowchart(self):
        f = idaapi.get_func(self.addr_fc)
        self.flowchart = idaapi.FlowChart(f)

    def coloring_bb(self, addr):
        self._set_bb_range(addr)
        for addr in range(self.startea, self.endea):
            idc.set_color(addr, idc.CIC_ITEM, 0x7fffff)  # olive
            # idc.set_color(addr, idc.CIC_ITEM, 0xffffff)  # olive

    def _set_bb_range(self, addr):
        for block in self.flowchart:
            if block.start_ea <= addr and block.end_ea > addr:
                self.startea, self.endea = block.start_ea, block.end_ea
                break


def set_color(target):
    ea = get_segm_by_sel(selector_by_name(".text"))
    funcs = list(Functions(get_segm_start(ea), get_segm_end(ea)))

    for funcea in target:
        if target[funcea]:
            if funcea not in funcs:
                if funcea >= get_segm_start(ea) and funcea <= get_segm_end(ea):
                    print(hex(funcea))
                continue
            cb = ColoringBB(funcea)
            # cb.coloring_bb(funcea)
            for block in target[funcea]:
                cb.coloring_bb(block)


target = {4196176: {4196176, 4196194}, 4196208: set(), 4196220: set(), 4196224: set(), 4196240: set(), 4196256: set(), 4196272: set(), 4196288: set(), 4196330: set(), 4196331: set(), 4196336: set(), 4196338: set(), 4196352: {4196392, 4196352}, 4196394: set(), 4196400: {4196456, 4196400}, 4196458: set(), 4196464: {4196464, 4196473}, 4196491: set(), 4196498: set(), 4196512: {4196400, 4196512}, 4196519: set(), 4196528: {4196609, 4196614, 4196710, 4196586, 4196688, 4196528, 4196628, 4196727}, 4196743: set(), 4196752: {4196960, 4196897, 4196931, 4196836, 4196841, 4196813, 4196909, 4196752, 4196977, 4196855, 4196984, 4196955}, 4196993: set(), 4197008: {4197184, 4197252, 4197191, 4197230, 4197135, 4197071, 4197008, 4197076, 4197117}, 4197260: set(), 4197264: {4197408, 4197475, 4197448, 4197293, 4197360, 4197264, 4197330, 4197462, 4197398, 4197432, 4197307, 4197372, 4197727}, 4197736: set(), 4197744: {4197744, 4197830, 4197798}, 4197845: set(), 4197856: set(), 4197860: set(), 7340032: set(), 7340040: set(), 7340048: set(), 7340056: set(), 7340064: set(), 8392784: set(), 8392792: set()}

set_color(target)
# set_color({0x401480:[0x4014EF]})