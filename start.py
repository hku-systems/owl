#!/usr/bin/env python
import os
def start_syzkaller():
	os.system("nohup ./fuzzers/syzkaller/bin/syz-manager -config ./fuzzers/syzkaller/my.cfg &")
if __name__ == '__main__':
	fp=open("owl.cfg","r")
	line=fp.readline()
	while line:
		if line=="on\n":
			on_mods=fp.readline()
			if "kernel" in on_mods:
				start_syzkaller()
		line=fp.readline()
