#!/usr/bin/env python
import pyinotify
import os
import syzkaller_hdl
rtl_dir="../report_trace_log"
abspath=os.path.abspath(rtl_dir)
len_abspath=len(abspath)
class NewFileHandler(pyinotify.ProcessEvent):
	def process_IN_CREATE(self, event):
		print "Creating:", event.pathname	
		relative_path=event.pathname[len_abspath+1:]
		if relative_path.startswith("syzkaller"):
			syzkaller_hdl.handle(event.pathname,relative_path)

def WatchNewFile():
	wm=pyinotify.WatchManager()
        handler=NewFileHandler()
	notifier = pyinotify.Notifier(wm, default_proc_fun=handler)
	wm.add_watch(rtl_dir, pyinotify.IN_CREATE, rec=True, auto_add=True)
	print "start monitoring rtl"
	notifier.loop()

if __name__ == '__main__':
	
	WatchNewFile()
