#!/usr/bin/env python
def handle(full_path,relative_path):
	print "syz called"
	l=len("syzkaller/")
	r_path=relative_path[l:]
	if r_path.startswith("crashes"):
		syzkaller_crash_hdl(full_path)
def syzkaller_crash_hdl(full_path):
	print 'xxx'
