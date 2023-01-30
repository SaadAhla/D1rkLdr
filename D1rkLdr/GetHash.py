import sys

def myHash(data):
    hash = 0x99
    for i in range(0, len(data)):
        hash += ord(data[i]) + (hash << 1)
    print (hash)
    return hash

myHash(sys.argv[1])