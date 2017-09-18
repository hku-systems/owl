#!/usr/bin/env python
def handle(full_path,relative_path):
	l=len("syzkaller/crashes/")
	r_path=relative_path[l:]
	print r_path
	if r_path.startswith("crashes"):
		crash_log(full_path,r_path)

def crash_log(full_path,r_path):
	print "crash called"
	clen=len("crashes/")
	rp=r_path[clen:]
	if rp.startswith("log"):
		ordinary_log()
	elif rp.startswith("repro"):
		if rp=="repro.prog":
			print "prog"
def ordinary_log():
	print "ord log"
