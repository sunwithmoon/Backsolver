def crc(prev, cur):
    prev = (prev >> 4) ^ (prev << 8)
    prev &= 65535
    prev = prev >> 1

    cur = (cur >> 4) ^ (cur << 8)
    cur &= 65535
    return cur ^ prev

# ends = [0x405392, 0x405397, 0x40539C, 0x4053A6]
# for end in ends:
print(crc(0x408F61 , 0x408F73))
# print(crc(0x408efa, 0x408eff))