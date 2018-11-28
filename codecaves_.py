#!/usr/bin/python3
try:
    import argparse
    import pefile
    import sys
except ImportError:
    print ("[+] Install modules required")
def cave_search(inputfile, cave_size, base):

    image_base = int(base, 16)
    min_cave = cave_size
    fname = inputfile
    pe = None

    try:
        pe = pefile.PE(fname)
    except IOError as e:
        print(e)
        

    print("[+] Minimum code cave size: %d" % min_cave)
    print("[+] Image Base:  0x%08X" % image_base)
    print("[+] Loading \"%s\"..." % fname)

    is_aslr = pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040

    if is_aslr:
        print("\n[!] ASLR is enabled.")

    file_open = open(fname, "rb")

    print("\n[+] Looking for code caves...")
    for section in pe.sections:
        if section.SizeOfRawData != 0:
            pos = 0
            count = 0
            file_open .seek(section.PointerToRawData, 0)
            data = file_open.read(section.SizeOfRawData)
            for byte in data:
                pos += 1
                if byte == 0x00:
                    count += 1
                else:
                    if count > min_cave:
                        raw_addr = section.PointerToRawData + pos - count - 1
                        vir_addr = image_base + section.VirtualAddress + pos - count - 1

                        print("[+] Code cave found in %s \tSize: %d bytes \tRA: 0x%08X \tVA: 0x%08X" % (section.Name.decode(), count, raw_addr, vir_addr))
                        count = 0
    
if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="C0d3 Cave in PE ")
    parser.add_argument("-f", "--file", dest="inputfile", action="store", required=True, help="PE file", type=str)
    parser.add_argument("-s", "--size", dest="size", action="store", default=300, help="cave size min", type=int)
    parser.add_argument("-b", "--base", dest="base", action="store", default="0x00400000", help="Image base", type=str)
    args = parser.parse_args()
    if args.inputfile:
        cave_search(args.inputfile, args.size, args.base)
    elif args.size:
        cave_search(args.inputfile, args.size, args.base)
    elif args.base:
        cave_search(args.inputfile, args.size, args.base)
    else:
        parser.print_help()
        exit()
