import argparse
import math
import pefile

def shannon_entropy(data):
    # 256 different possible values
    possible = dict(((chr(x), 0) for x in range(0, 256)))

    for byte in data:
        possible[chr(byte)] +=1

    data_len = len(data)
    entropy = 0.0

    # compute
    for i in possible:
        if possible[i] == 0:
            continue

        p = float(possible[i] / data_len)
        entropy -= p * math.log(p, 2)
    return entropy

def sections_entropy(path):
    pe = pefile.PE(path)
    for section in pe.sections[:3]:
        print(section.Name.decode('utf-8'))
        print("\tvirtual address: " + hex(section.VirtualAddress))
        print("\tvirtual size: " + hex(section.Misc_VirtualSize))
        print("\traw size: " + hex(section.SizeOfRawData))
        print ("\tentropy: " + str(shannon_entropy(section.get_data())))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-f','--file', required = True, help = "target file")
    args = vars(parser.parse_args())
    target_file = args['file']
    with open(target_file, 'rb') as f:
        sections_entropy(target_file)
