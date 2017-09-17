#!/usr/bin/env python
import pyinotify

class NewFileHandler(pyinotify.ProcessEvent):
	
		

def WatchNewFile():
	wm=pyinotify.WatchManager()
        handler=NewFileHandler()

if __name__ == '__main__':
	WatchNewFile()
