#!/usr/bin/env python
import pyinotify

class NewFileHandler(pyinotify.ProcessEvent):
	def process_IN_CREATE(self, event):
		print "Creating:", event.pathname	
		

def WatchNewFile():
	wm=pyinotify.WatchManager()
        handler=NewFileHandler()
	notifier = pyinotify.Notifier(wm, default_proc_fun=handler)
	wm.add_watch('../report_trace_log', pyinotify.IN_CREATe, rec=True, auto_add=True)
	print "start monitoring rtl"
	notifier.loop()

if __name__ == '__main__':
	WatchNewFile()
