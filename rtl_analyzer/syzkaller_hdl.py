#!/usr/bin/env python
import os
import time
def handle(full_path,filename):
	if filename.startswith("log"):
		fp=open(full_path,"r")
		content=fp.read()
		if "executor failed: failed to mkdir (errno 28)" in content:
			fp.close()
			print "Deleted: "+full_path
			os.remove(full_path)
		else:
			fp.close()
	elif filename.startswith("report"):
		print "do sth"
	elif filename=="repro.prog":
		print "do sth to prog."
	elif filename=="repro.log":
		print "do sth"
