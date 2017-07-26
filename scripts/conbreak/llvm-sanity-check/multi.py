#!/usr/bin/python2.7

import lldb
import threading

lock = threading.Lock()

def init():
	target = lldb.debugger.GetSelectedTarget()
	bp = target.BreakpointCreateByName("func")
	bp.SetScriptCallbackFunction("multi.bp_callback")

	# Start another thread after waiting 5 seconds
	threading.Timer(5, func).start()

def func():
	print "RESUMING ALL THREADS"

	process = lldb.debugger.GetSelectedTarget().GetProcess()

	# Is there a way to stop a process so we can resume threads w/o printing
	# out debugging info for all the hit breakpoints?

	for t in process:
		if t.Resume() == False:
			print "### ERROR IN THREAD.RESUME ###"


def bp_callback(frame, bp_loc, dict):
	lock.acquire()

	thread = frame.GetThread()
	process = thread.GetProcess()

	thread.Suspend()
	process.Continue()

	lock.release()	

def __lldb_init_module(debugger, dict):
	init()
	debugger.HandleCommand('run')


