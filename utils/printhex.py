import collections

def print_json(data, level=0):
    print('\t' * level + '{')
    for key in data:
        if type(data[key]) == dict:
            print('\t' * level + key + ':')
            print_json(data[key], level + 1)
        else:
            print("{}{}:\n{}{}".format('\t' * level, key, '\t' * (level + 1), data[key]))
    print('\t' * level + '}')

def recursive_hex_change(data):
    new_data = []
    for d in data:
        if isinstance(d, collections.Iterable):
            new_data.append(recursive_hex_change(d))
        elif type(d)==int:
            new_data.append(hex(d))
        else:
            new_data.append(d)
    return type(data)(new_data)
