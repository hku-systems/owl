#!/usr/bin/env python
import pyinotify
import os
import syzkaller_hdl
rtl_dir="../report_trace_log"
abspath=os.path.abspath(rtl_dir)
len_abspath=len(abspath)

def ClassifyDispatch(full_path,relative_path):
        #print "* ",full_path, "\n- ",relative_path
	if relative_path.startswith("syzkaller"):
                syzkaller_hdl.handle(full_path,relative_path)

def ScanFolder():
	list_dir=os.walk(rtl_dir)
	for root, dirs, files in list_dir:
		for f in files:
			relative_path=(os.path.join(root,f))[len(rtl_dir)+1:]		
			full_path=os.path.abspath(os.path.join(root,f))
			ClassifyDispatch(full_path,relative_path)


class NewFileHandler(pyinotify.ProcessEvent):
	def process_IN_CREATE(self, event):
		print "Creating:", event.pathname	
		relative_path=event.pathname[len_abspath+1:]
		ClassifyDispatch(event.pathname,relative_path)

def WatchNewFile():
	wm=pyinotify.WatchManager()
        handler=NewFileHandler()
	notifier = pyinotify.Notifier(wm, default_proc_fun=handler)
	wm.add_watch(rtl_dir, pyinotify.IN_CREATE, rec=True, auto_add=True)
	print "start monitoring rtl"
	notifier.loop()

if __name__ == '__main__':
	ScanFolder()
	#WatchNewFile()
