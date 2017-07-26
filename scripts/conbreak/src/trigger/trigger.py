#!/usr/bin/python2.7
import lldb
import sys
import random
import time
import threading
import re
import subprocess
from inspect import currentframe, getframeinfo

# Regular expression to match the input
regBreakpoint = re.compile(".*\(([a-zA-Z0-9_~\./\-]*):([0-9]*)(:[0-9]*)?\).*") 

# USER SET GLOBAL VARIABLES
WAIT_TIME         = 0.5               # Timeout (in sec, ie. 0.1 = 100ms), default = 1
KILL_TIME         = 5                 # Time to wait after last BP until lldb is killed
TERM_TIME         = 20                # Timeout for no activity (non-interactive only)
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

# Source code for read & write
bp_source = []
bp_location = []

def set_trigger(in_write, in_read):
    out("Setting breakpoints...")
    out(in_write)
    out(in_read)
    target = lldb.debugger.GetSelectedTarget()
    lldb.debugger.SetAsync(True)

    global FILE_READ
    global LINE_NUM_READ
    global FILE_WRITE
    global LINE_NUM_WRITE

    tokens_write = in_write.split(":")
    tokens_read = in_read.split(":")
    bp_location.append(tokens_write)
    bp_location.append(tokens_read)

    FILE_READ = tokens_read[0]
    LINE_NUM_READ = int(tokens_read[1])

    FILE_WRITE = tokens_write[0]
    LINE_NUM_WRITE = int(tokens_write[1])

    bp_write = target.BreakpointCreateByLocation(FILE_WRITE, LINE_NUM_WRITE)
    # We only set one breakpoint if the race happens in the same line
    if bp_source[0] != bp_source[1]:
        bp_read = target.BreakpointCreateByLocation(FILE_READ, LINE_NUM_READ)
    else:
        out("####### WARN: READ & WRITE ARE THE SAME! #######")
    
    bp_write.SetScriptCallbackFunction("trigger.write_callback")
    if bp_source[0] != bp_source[1]:
        bp_read.SetScriptCallbackFunction("trigger.read_callback")

    update_timer()
    timer()

    out("Breakpoint initialization done!")
    return

# Output wrapper function
def out(msg):
    if INTERACTIVE:
        print msg

    print_lock.acquire()
    OUTPUT_FD.write(str(msg) + "\n")
    OUTPUT_FD.flush()
    print_lock.release()

# Wrapper for ensuring clean exit
def terminate():
    # Wait for all IO to finish
    OUTPUT_FD.close()

    if INTERACTIVE:
        print "Exit script."
        exit(1)
    else:
        lldb.SBDebugger.Terminate()

    # Send garbage command to lldb, Expect will pick it up and 
    # kill the program from the outside
    #lldb.debugger.HandleCommand("@@@EXIT@@@")

    while True:
        pass
    return

def thread_liveness_check(ID):
    # This function returns the list of thread id of unexpected breakpoints
    thread_list = [idx for idx, obj in enumerate(OBJ_ARR) if obj[-1] == ID]
    if thread_list:
        out("####### WARN: {0} Unexpectedly resumed. #######".format(ID))
    return thread_list

def untracked_breakpoint_check(frame):
    # This function returns a list of Thread object that are being hit
    # simultaneously. The caller needs to hold a lock.
    thread = frame.GetThread()
    process = thread.GetProcess()
    ID = thread.GetThreadID()
    thread_id_list = [obj[-1] for obj in OBJ_ARR]
    untracked_thread_list = []
    untracked_thread_id_list = []
    stopped_thread_id_list = []

    # Find the breakpoints that are not being tracked.
    # Note that this list also contains the current triggering breakpoint
    for thd in process:
        id = thd.GetThreadID()
        if thd.GetStopReason() == lldb.eStopReasonBreakpoint:
            stopped_thread_id_list.append(id)
            if id not in thread_id_list:
                untracked_thread_list.append(thd)
                untracked_thread_id_list.append(id)
    
    if len(untracked_thread_list) > 1:
        out("####### WARN: Multiple breakpoints are hit in CALLBACK! #######")
        out(untracked_thread_id_list)
    elif len(untracked_thread_list) < 1:
        out("####### WARN: No breakpoints are hit in CALLBACK! #######")
        out(stopped_thread_id_list)

    return untracked_thread_list

# This is a blocking function
def continue_process(process):
    if process.is_stopped:
        error = process.Continue()
        while not error.Success():
            out("####### WARN: process.Continue() FAILED! TRYING AGAIN! #######")
            error = process.Continue()
            time.sleep(1)

def stop_process(process):
    if not process.is_stopped:
        error = process.Stop()
        while not error.Success():
            out("####### WARN: process.Stop() FAILED! TRYING AGAIN! #######")
            error = process.Stop()
            time.sleep(1)

# Put all thread states from suspend to resume 
# except_set contains excepted threads
def resume_threads(process, except_set):
    for thd in process:
        if thd.GetThreadID() in except_set:
            continue
        if thd.IsSuspended():
            while not thd.Resume():
                out("####### WARN: thread.Resume() FAILED! TRYING AGAIN! #######")
                time.sleep(1)
    out("####### INFO: THREADS RESUMED. #######")

def breakpoint_match_check(process, addrs, loc_type, ID):
    for obj in addrs:
        if loc_type == 0:
            out(str(time.time()) + " WRITE:  [" + str(ID) + "] Checking " + str(obj) + "...")
        elif loc_type == 1:
            out(str(time.time()) + " READ:  [" + str(ID) + "] Checking " + str(obj) + "...")
        else:
            out("####### ERROR: loc_type can only be 0 or 1 #######")
            terminate()
        
    if loc_type == 0:
        addrs.append("W")
    elif loc_type == 1:
        addrs.append("R")
    addrs.append(ID)

    matches = match(addrs)
    if len(matches) > 0:
        if loc_type == 0:
            out(">>>>>>>>>> WRITE:  [" + str(ID) + "] Found match!")
        elif loc_type == 1:
            out(">>>>>>>>>> READ:  [" + str(ID) + "] Found match!")

        except_set = set()
        for m in matches:
            out("addr=" + m[0] + "  tid1=" + str(m[1]) + "  tid2=" + str(ID))
            except_set.add(m[1])
            except_set.add(ID)

        out("**************************************************************")
        out("**************************** HALT ****************************")
        out("**************************************************************")

        resume_threads(process, except_set)
        STATUS_FOUND = True
        stop_process(process)
        out("####### SUCCESS: MATCH FOUND #######")
        terminate()

    else:
        update_timer()
        OBJ_ARR.append(addrs)
        out(">>>>>>> INFO: RECORD THREAD " + str(ID) + " >>>>>>>" )
        # Randomly select a thread to be released if all threads are suspended
        if all_bp_hit():
            release_bp()
    return
    
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
            continue_process(process)

        if not INTERACTIVE and len(OBJ_ARR) == 0 and time.time() - LAST_BREAK > KILL_TIME:
            out("####### TERMINATE: No breakpoints hit in " + str(KILL_TIME) + " sec...")
            terminate()

    elif not INTERACTIVE and time.time() - LAST_BREAK > TERM_TIME:
        out("####### TERMINATE: Unable to start up after " + str(TERM_TIME) + " sec...")
        terminate()

    process_lock.release()

    if STATUS_FOUND:
        out("####### STATUS: MATCH FOUND #######")
        terminate()

    # We don't care about timing drift, we just want timer() to be called periodically
    threading.Timer(0.1, timer).start()

def update_timer():
    timer_lock.acquire()

    global LAST_BREAK
    LAST_BREAK = time.time()

    timer_lock.release()
    return

# Check to see if every thread is at a breakpoint
# TODO: We need a better way to check if all threads are currently suspended..
# Sometimes not all threads will be suspended but program still stops, leaving 
# the job of releasing BPs to fall back to the timeout
def all_bp_hit():
    for t in lldb.debugger.GetSelectedTarget().GetProcess():
        if not t.IsSuspended():
            return False
    return True

# Randomly choose a thread to be released from breakpoint.
# Expects process to already be stopped.  Will resume thread, but process.Continue() 
# to be called by calling function
def release_bp():
    global OBJ_ARR
    process = lldb.debugger.GetSelectedTarget().GetProcess()
    # Check if process is invalid, can cause errors
    if process.IsValid() == False:
        out("######## WARN: PROCESS IS INVALID ########")
        return False

    obj_arr_len = len(OBJ_ARR)

    # No more suspended threads...
    if obj_arr_len == 0:
        return False

    rand = random.randrange(0, obj_arr_len)
    thread = process.GetThreadByID(OBJ_ARR[rand][-1])
    # Make sure process is stopped before modifying thread states
    stop_process(process)

    while not thread.Resume():
        out("####### WARN: thread.Resume() FAILED! TRYING AGAIN! #######")
        time.sleep(1)
    del OBJ_ARR[rand]

    out(str(time.time()) + " >>>>>>> INFO: Thread " +
        str(thread.GetThreadID()) + " is released. >>>>>>>")
    return True


# Get address of all variables on line reported by TSAN
def get_addr(frame, src_line):
    # Sanity check
    if not frame:
        out(" ####### ERROR: Couldn't obtain frame ####### ")
        terminate()
    # Needs some refinement.  Hacky so just exit on error
    try:
        src_line = [src_line]
        break_chars = [" ", "\n", "\t", ",", ";", "(", ")", "="]

        # Split source line up using break_chars as delimiters
        # Split function won't handle consecutive delimiters correctly
        for char in break_chars:
            src_line = [s.split(char) for s in src_line]
            src_line = [item for sublist in src_line for item in sublist]

        # Remove blank strings from list
        #src_line = filter(None, src_line)

        # Remove escape characters (can cause errors)
        escapes = ''.join([chr(char) for char in range(1, 32)])
        src_line = [c for c in src_line if c.translate(None, escapes) != ""]

        # Remove operators
        break_chars = ["++", "--", "!", "*", "&"]
        for op in break_chars:
            src_line = [token.replace(op, "") for token in src_line]

        # Remove blank strings again..
        src_line = filter(None, src_line)

        if not src_line:
            out("####### WARN: Couldn't obtain source code line #######")

        # Try to find a variable that matches a token and save its address
        addrs = []
        out(src_line)
        for token in src_line:
            # TODO: This function randomly fails for unknown reasons.
            obj = frame.GetValueForVariablePath(token)

            # Very hacky way to verify extracted variable is valid
            # TODO: Is there a better way to do this?
            # obj.IsValid() does not work, frame.FindVariable() cannot find globals,
            # target.FindFirstGlobalVariable() can't resolve complex expressions.  Only 
            # method I haven't really tried is manually searching frame.GetVariables()
            if str(obj.GetAddress()) != "No value":
                addrs.append(obj.GetAddress().__hex__())
        if len(addrs) == 0:
            out("####### ERROR: No variables found! Stop!! #######")
            terminate()
    
    except (KeyboardInterrupt, SystemExit):
        raise

    except:
        out("####### ERROR: Unable to extract variable name from source #######")
        out(sys.exc_info()[0])
        terminate()

    return addrs

# Match if addresses match and instructions differ
def match(arr):
    matches = []

    for obj in OBJ_ARR:
        # Only considered a match if tid and instructions differ
        if obj[-1] != arr[-1]:
            if bp_source[0] == bp_source[1] or obj[-2] != arr[-2]: 
                # Check through all watched addresses
                for addr1 in obj[:-2]:
                    if addr1 in arr[:-2]:
                        matches.append([addr1, obj[-1]])
                    
    return matches

def read_callback(frame, bp_loc, dict):
    process_lock.acquire()

    global OBJ_ARR
    global RUNNING
    global STATUS_FOUND

    thread = frame.GetThread()
    process = thread.GetProcess()
    ID = thread.GetThreadID()
    out(">>>>>>> INFO: READ THREAD " + str(ID) + " IS TRIGGERED >>>>>>>" )

    stop_process(process)

    # For some unknown reason, threads can resume unexpectedly. So we use
    # this sanitiy check to see whether this happens.
    #thread_list = thread_liveness_check(ID)
    #for i in thread_list:
        #del OBJ_ARR[i]
    
    RUNNING = False
    
    untracked_thread_list = untracked_breakpoint_check(frame)

    for thd in untracked_thread_list:
        # Suspend all the untraced thread at breakpoint
        while not thd.Suspend():
            out("####### WARN: thread.Suspend() FAILED! TRYING AGAIN! #######")
            time.sleep(1)
        fr = thd.GetFrameAtIndex(0)
        if fr.GetLineEntry().GetLine() == int(bp_location[0][1]):
            addrs = get_addr(fr, bp_source[0])
            breakpoint_match_check(process, addrs, 0, thd.GetThreadID())
        elif fr.GetLineEntry().GetLine() == int(bp_location[1][1]):
            addrs = get_addr(fr, bp_source[1])
            breakpoint_match_check(process, addrs, 1, thd.GetThreadID())
        else:
            out("####### ERROR: thd.GetSelectedFrame FAILED. #######") 
            terminate()

    RUNNING = True
    continue_process(process)

    process_lock.release()
    return

def write_callback(frame, bp_loc, dict):
    process_lock.acquire()

    global OBJ_ARR
    global RUNNING
    global STATUS_FOUND

    thread = frame.GetThread()
    process = thread.GetProcess()
    ID = thread.GetThreadID()
    out(">>>>>>> INFO: WRITE THREAD " + str(ID) + " IS TRIGGERED >>>>>>>" )

    stop_process(process)
    RUNNING = False

    # For some unknown reason, threads can resume unexpectedly. So we use
    # this sanitiy check to see whether this happens.
    thread_list = thread_liveness_check(ID)
    for i in thread_list:
        del OBJ_ARR[i]
    
    untracked_thread_list = untracked_breakpoint_check(frame)

    for thd in untracked_thread_list:
        # Suspend all the untraced thread at breakpoint
        while not thd.Suspend():
            out("####### WARN: thread.Suspend() FAILED! TRYING AGAIN! #######")
            time.sleep(1)
        fr = thd.GetSelectedFrame()
        if fr.GetLineEntry().GetLine() == int(bp_location[0][1]):
            addrs = get_addr(fr, bp_source[0])
            breakpoint_match_check(process, addrs, 0, thd.GetThreadID())
        elif fr.GetLineEntry().GetLine() == int(bp_location[1][1]):
            addrs = get_addr(fr, bp_source[1])
            breakpoint_match_check(process, addrs, 1, thd.GetThreadID())
        else:
            out("####### ERROR: thd.GetSelectedFrame FAILED. #######") 
            terminate()

    RUNNING = True
    continue_process(process)

    process_lock.release()
    return

def __lldb_init_module(debugger, dict):
    # Grab arguments from argument file
    #with open(ARG_FILE) as f:
        #args = f.readline()

    global OUTPUT_FD
    OUTPUT_FD = open(OUTPUT_FILENAME, "w")
    debugger.HandleCommand("log enable -f log.txt lldb api")
    filenames = []

    # Parse out filename and lineno from parsed tsan report
    with open(TSAN_REPORT_FILE) as f:
        lines = f.readlines()
        for line in lines:
            bp = regBreakpoint.match(line)
            if not bp:
                out("####### ERROR: FAIL TO PARSE INPUT #######")
                terminate()
            filenames.append(bp.group(1) + ":" + bp.group(2))
            # Notice that we require a symbolic link of the source code folder
            # with name source_code. LLDB's API to read file is so unreliable.
            c1 = "find source_code -name {0} -follow".format(bp.group(1))
            p1 = subprocess.Popen(c1.split(), stdout=subprocess.PIPE)
            #output, error = p1.communicate()
            c2 = "xargs sed -n {0}p".format(bp.group(2))
            p2 = subprocess.Popen(c2.split(), stdout=subprocess.PIPE, stdin=p1.stdout)
            output, error = p2.communicate()

            bp_source.append(output)
            if error:
                # You need to create a symbolic link of the source code
                out("####### ERROR: FAIL TO GRAB SOURCE CODE #######")
                terminate()

    out("Read input done!")

    # Setup and start
    set_trigger(filenames[0], filenames[1])
    #debugger.HandleCommand("run " + args[:-1])
