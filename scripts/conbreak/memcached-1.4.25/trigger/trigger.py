#!/usr/bin/python2.7

import lldb
import sys
import random
import time
import threading

# USER SET GLOBAL VARIABLES
WAIT_TIME         = 1                 # Timeout (in sec, ie. 0.1 = 100ms), default = 1
KILL_TIME         = 5                 # Time to wait after last BP until lldb is killed
TERM_TIME         = 30                # Timeout for no activity (non-interactive only)
INTERACTIVE       = 0                 # Default = 1, set to 0 when using wrapper script
TSAN_REPORT_FILE  = "report.txt"      # File with parsed TSAN report
ARG_FILE          = "args.txt"        # Arguments for trigger.py and target executable
OUTPUT_FILENAME   = "lldb_out.txt"    # Output file if INTERACTIVE = 0

# DO NOT CHANGE
LAST_BREAK = 0
RUNNING = False
OBJ_ARR = []
STATUS_FOUND = False
OUTPUT_FD = None

FILE_READ = ""
LINE_NUM_READ = 0
FILE_WRITE = ""
LINE_NUM_WRITE = 0

# Locks
# TODO: Improve granularity of locks
timer_lock = threading.Lock()
print_lock = threading.Lock()
process_lock = threading.Lock()


def set_trigger(in_read, in_write):
	out("Setting breakpoints...")
	target = lldb.debugger.GetSelectedTarget()

	global FILE_READ
	global LINE_NUM_READ
	global FILE_WRITE
	global LINE_NUM_WRITE

	tokens_read = in_read.split(":")
	tokens_write = in_write.split(":")

	FILE_READ = tokens_read[0]
	LINE_NUM_READ = int(tokens_read[1])

	FILE_WRITE = tokens_write[0]
	LINE_NUM_WRITE = int(tokens_write[1])

	bp_read = target.BreakpointCreateByLocation(FILE_READ, LINE_NUM_READ)
	bp_write = target.BreakpointCreateByLocation(FILE_WRITE, LINE_NUM_WRITE)

	bp_read.SetScriptCallbackFunction("trigger.read_callback")
	bp_write.SetScriptCallbackFunction("trigger.write_callback")

	update_timer()
	timer()

	out("Configuration done!")


# Output wrapper function
def out(msg):
	if INTERACTIVE:
		print msg
		return

	print_lock.acquire()
	OUTPUT_FD.write(str(msg) + "\n")
	OUTPUT_FD.flush()
	print_lock.release()


# Wrapper for ensuring clean exit
def kill():
	if INTERACTIVE:
		exit()

	OUTPUT_FD.close()
	
	# Send garbage command to lldb, Expect will pick it up and 
	# kill the program from the outside
	lldb.debugger.HandleCommand("@@@EXIT@@@")
	exit()


# Release a thread if stable state is reached
def timer():
	process_lock.acquire()

	global RUNNING

	if RUNNING:
		if time.time() - LAST_BREAK > WAIT_TIME:
			process = lldb.debugger.GetSelectedTarget().GetProcess()

			RUNNING = False

			if release_bp():
				update_timer()

			RUNNING = True
			process.Continue()

		if not INTERACTIVE and len(OBJ_ARR) == 0 and time.time() - LAST_BREAK > KILL_TIME:
			out("TERMINATE: No breakpoints hit in " + str(KILL_TIME) + " sec...")
			kill()

	elif not INTERACTIVE and time.time() - LAST_BREAK > TERM_TIME:
		out("TERMINATE: Unable to start up after " + str(TERM_TIME) + " sec...")
		kill()

	process_lock.release()

	if STATUS_FOUND:
		out("### STATUS: MATCH FOUND ###")
		exit()

	# We don't care about timing drift, we just want timer() to be called periodically
	threading.Timer(0.1, timer).start()

def update_timer():
	timer_lock.acquire()

	global LAST_BREAK
	LAST_BREAK = time.time()

	timer_lock.release()


# Check to see if every thread is at a breakpoint
# TODO: We need a better way to check if all threads are currently suspended..
# Sometimes not all threads will be suspended but program still stops, leaving 
# the job of releasing BPs to fall back to the timeout
def all_bp_hit():
	for t in lldb.debugger.GetSelectedTarget().GetProcess():
		if not t.IsSuspended():
			return False

	return True

	# Old mechanism.  Just check if 10 threads are suspended
#	c = 0
#	res = False
#
#	for t in lldb.debugger.GetSelectedTarget().GetProcess():
#		if t.IsSuspended():
#			c += 1
#
#	if c >= 10:
#		res = True
#	
#	return res


# Randomly choose a thread to be released from breakpoint.
# Expects process to already be stopped.  Will resume thread, but process.Continue() 
# to be called by calling function
def release_bp():
	process = lldb.debugger.GetSelectedTarget().GetProcess()

	# Check if process is invalid, can cause errors
	if process.IsValid() == False:
		out("######## WARNING: PROCESS IS INVALID ########")
		return False

	global OBJ_ARR

	obj_arr_len = len(OBJ_ARR)

	# No more suspended threads...
	if obj_arr_len == 0:
		return False

	rand = random.randrange(0, obj_arr_len)
	thread = process.GetThreadByID(OBJ_ARR[rand][-1])

	out(str(time.time()) + " >>>>>>>>>> INFO: Attempting to release thread " + 
		str(thread.GetThreadID()))

	# Make sure process is stopped before modifying thread states
	if not process.is_stopped:
		process.Stop()

	if thread.Resume() == False:
		out("### ERROR IN THREAD.RESUME() ###")
		return False

	del OBJ_ARR[rand]
	return True


# Get address of all variables on line reported by TSAN
def get_addr(frame, filename, line_num):
	filespec = lldb.SBFileSpec(filename, False)
	if not filespec.IsValid():
		out(" ####### ERROR: Filespec is invalid ####### ")
		kill()
	
	target = lldb.debugger.GetSelectedTarget()
	source_mgr = target.GetSourceManager()
	stream = lldb.SBStream()
	source_mgr.DisplaySourceLinesWithLineNumbers(filespec, line_num, 0, 0, "", stream)

	# Needs some refinement.  Hacky so just exit on error
	try:
		src_line = stream.GetData().split("\n")[0]

#		out(">>>>>>>>> src=" + str(src_line))

		src_line = [src_line]
		break_chars = [" ", "\n", "\t", ",", ";", "(", ")"]

		# Split source line up using break_chars as delimiters
		for char in break_chars:
			src_line = [s.split(char) for s in src_line]
			src_line = [item for sublist in src_line for item in sublist]

		# Remove blank strings from list
		src_line = filter(None, src_line)

		# Remove escape characters (can cause errors)
		escapes = ''.join([chr(char) for char in range(1, 32)])
		src_line = [c for c in src_line if c.translate(None, escapes) != ""]

		# Remove operators
		break_chars = ["++", "--", "!", "*", "&"]
		for op in break_chars:
			src_line = [token.replace(op, "") for token in src_line]

		# Remove blank strings again..
		src_line = filter(None, src_line)

#		out(">>>>>>>>> tokens=" + str(src_line))

		# Try to find a variable that matches a token and save its address
		addrs = []
		for token in src_line:
			obj = frame.GetValueForVariablePath(token)

			# Very hacky way to verify extracted variable is valid
			# TODO: Is there a better way to do this?
			# obj.IsValid() does not work, frame.FindVariable() cannot find globals,
			# target.FindFirstGlobalVariable() can't resolve complex expressions.  Only 
			# method I haven't really tried is manually searching frame.GetVariables()
			if str(obj.GetAddress()) != "No value":
				addrs.append(obj.GetAddress().__hex__())
	
	except (KeyboardInterrupt, SystemExit):
		raise

	except:
		out("####### ERROR: Unable to extract variable name from source #######")
		out(sys.exc_info()[0])
		kill()

	if len(addrs) == 0:
		out("####### ERROR: No variables found #######")
		kill()

	return addrs


# Match if addresses match and instructions differ
def match(arr):
	matches = []

	for obj in OBJ_ARR:

		# Only considered a match if tid and instructions differ
		if obj[-1] != arr[-1] and obj[-2] != arr[-2]:

			# Check through all watched addresses
			for addr1 in obj[:-2]:
				for addr2 in arr[:-2]:

					# Add address and tid to list if addresses match
					if addr1 == addr2:
						matches.append([addr1, obj[-1]])

	return matches


def read_callback(frame, bp_loc, dict):
	thread = frame.GetThread()
	process = thread.GetProcess()
	ID = thread.GetThreadID()

	process_lock.acquire()

	global OBJ_ARR
	global RUNNING
	global STATUS_FOUND

	RUNNING = False
	thread.Suspend()

	addrs = get_addr(frame, FILE_READ, LINE_NUM_READ)

	for obj in addrs:
		out(str(time.time()) + " READ:  [" + str(ID) + "] Checking " + obj + "...")

	addrs.append("R")
	addrs.append(ID)

	matches = match(addrs)
	if len(matches) > 0:
		out(">>>>>>>>>> READ:  [" + str(ID) + "] Found match!")

		for m in matches:
			out("addr=" + m[0] + "  tid1=" + str(m[1]) + "  tid2=" + str(ID))

		out("**************************************************************")
		out("**************************** HALT ****************************")
		out("**************************************************************")

		STATUS_FOUND = True
		process.Stop()

		if not INTERACTIVE:
			kill()

	else:
		update_timer()

		OBJ_ARR.append(addrs)

		# Randomly select a thread to be released if all threads are suspended
		if all_bp_hit():
			release_bp()

		RUNNING = True
		process.Continue()

	process_lock.release()


def write_callback(frame, bp_loc, dict):
	thread = frame.GetThread()
	process = thread.GetProcess()
	ID = thread.GetThreadID()

	process_lock.acquire()

	global OBJ_ARR
	global RUNNING

	RUNNING = False
	thread.Suspend()

	addrs = get_addr(frame, FILE_WRITE, LINE_NUM_WRITE)

	for obj in addrs:
		out(str(time.time()) + " WRITE: [" + str(ID) + "] Setting  " + obj + "...")

	addrs.append("W")
	addrs.append(ID)

	matches = match(addrs)
	if len(matches) > 0:
		out(">>>>>>>>>> WRITE: [" + str(ID) + "] Found match!")

		for m in matches:
			out("addr=" + m[0] + "  tid1=" + str(m[1]) + "  tid2=" + str(ID))

		out("**************************************************************")
		out("**************************** HALT ****************************")
		out("**************************************************************")

		STATUS_FOUND = True
		process.Stop()

		if not INTERACTIVE:
			kill()

	else:
		update_timer()

		OBJ_ARR.append(addrs)

		# Randomly select a thread to be released if all threads are suspended
		if all_bp_hit():
			release_bp()

		RUNNING = True
		process.Continue()

	process_lock.release()


def __lldb_init_module(debugger, dict):
	# Grab aruments from argument file
	with open(ARG_FILE) as f:
		args = f.readline()

	if not INTERACTIVE:
		global OUTPUT_FD
		OUTPUT_FD = open(OUTPUT_FILENAME, "w")

	# Parse out filename and lineno from parsed tsan report
	with open(TSAN_REPORT_FILE) as f:
		lines = f.readlines()

		# "[func_name] (filename:lineno)" -> "filename:lineno"
		filenames = [line.rstrip().split(" ")[1][1:-1] for line in lines]

	out("Setting trigger...")

	# Setup and start
	set_trigger(filenames[1], filenames[0])
	debugger.HandleCommand("run " + args[:-1])






