#!/usr/bin/python2.7

import lldb
import commands
import argparse
import threading
import sys

counter = 0

def set_trigger():
	print "Setting breakpoints in mod_mem_cache.c at lines 354 and 653..."
	target = lldb.debugger.GetSelectedTarget()

	#threading.Timer(10, f).start()

	bp_read = target.BreakpointCreateByLocation("test.c", 12)
	bp_write = target.BreakpointCreateByName("set_status")

	bp_read.SetScriptCallbackFunction("trig1.read_callback")
	bp_write.SetScriptCallbackFunction("trig1.write_callback")
	print("Configuration done!")


def f():
	print "RESUMING ALL THREADS"

	p = lldb.debugger.GetSelectedTarget().GetProcess()
	for t in p:
		t.Resume()

	p.Continue()


def read_callback(frame, bp_loc, dict):
	thread = frame.GetThread()
	process = thread.GetProcess()
	ID = thread.GetThreadID()

	# Was trying to print out status variable... how do you get global vars?
	#obj = str(frame.FindVariable("status")).split()[-1]
	#print "READ: tid=" + str(ID) + "   status=" + obj
	
	global counter

	counter += 1
	if counter == 20:
		for t in process:
			t.Resume()

	thread.Resume()
	process.Continue()


def write_callback(frame, bp_loc, dict):
	thread = frame.GetThread()
	process = thread.GetProcess()
	ID = thread.GetThreadID()

	print ">>>>>>>>>> SUSPENDING WRITE THREAD"

	thread.Suspend()
	process.Continue()
	

def __lldb_init_module(debugger, dict):
    #debugger.HandleCommand('command script add -f trigger.set_trigger trig')
    #print "The \"trig\" python command has been installed and is ready for use."
	print "Setting trigger..."
	set_trigger()
	print "Starting server..."
	debugger.HandleCommand('run')






