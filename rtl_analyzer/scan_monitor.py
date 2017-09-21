#!/usr/bin/env python
import pyinotify
import os
import syzkaller_hdl
rtl_dir="../report_trace_log/"
abspath=os.path.abspath(rtl_dir)
len_abspath=len(abspath)
syz_crash="syzkaller/crashes/"
def ClassifyDispatch(full_path,relative_path):
	if relative_path.startswith(syz_crash):
                syzkaller_hdl.handle(full_path,os.path.basename(full_path))

def ScanFolder():
	if os.path.exists(rtl_dir+syz_crash):
		list_dir=os.walk(rtl_dir+syz_crash)
		for root, dirs, files in list_dir:
			for crash_dir in dirs:		
				list_crash=os.walk(rtl_dir+syz_crash+crash_dir)
				for c_root,c_dir,c_files in list_crash:
					for crash_file in c_files:
						syzkaller_hdl.handle(os.path.abspath(os.path.join(c_root,crash_file)),crash_file)	



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
	WatchNewFile()



#may need to do sth (kill all started components) before exit
