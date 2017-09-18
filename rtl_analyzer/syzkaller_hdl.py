#!/usr/bin/env python
def handle(full_path,relative_path):
	l=len("syzkaller/")
	r_path=relative_path[l:]
	if r_path.startswith("crashes"):
		crash_log(full_path,r_path)
def crash_log(full_path,r_path):
	clen=len("crashes/")
	rp=r_path[clen:]
	if rp.startswith("log"):
		ordinary_log()
	elif rp.startswith("repro"):
		if rp=="repro.prog":
			
def ordinary_log():
	print "ord log"

