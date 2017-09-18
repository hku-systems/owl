#!/usr/bin/env python
if __name__ == '__main__':
	fp=open("owl.cfg","r")
	line=fp.readline()
	while line:
		if line=="on\n":
			on_mods=fp.readline()
			print "cfg is ", on_mods
		line=fp.readline()
