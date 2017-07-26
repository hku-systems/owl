# Trigger -- LLDB Data Race Verifier
### Description
Trigger is a dynamic data race verifier that leverages LLDB's Python API on data race reports.  We aim to provide useful filtered TSAN(thread sanitizer) reports to developers in an efficient and practical manner.  This tool was developed to be used within the OWL framework for detecting and exploiting concurrency bugs in real world C applications.  For more information, please read our paper [here](http://www.nyan.cat/).

### Setup
Please ensure you have lldb-3.8.0 and its required dependencies installed before using ConBreak.  Please refer to the README at the root of this repository for more installation information.  Trigger currently has two execution modes: interactive and non-interactive.  Both have similar setup processes.
 * At Trigger's root you will find `trigger/` and `wrapper.sh`
 * `wrapper.sh` is the main shell script that will handle Trigger's execution
 * The `trigger/` directory contains all of Trigger's configuration and source files
 * Start by creating a symlink called `target` to your target program's executable
 * Create a file called `args.txt` that contains all the arguments to be passed to the selected executable
 * Create a folder called `tsan_reports/` that contains files each with one parsed tsan report
 * Create a shell script called `benchmark.sh` that will run your test suite on the executable
 * Adjust parameters at the top of `trigger.py` accordingly (eg. `INTERACTIVE = 1` for interactive mode)

### Usage
To run Trigger in non-interactive mode, simply execute the `wrapper.sh` script.  Trigger will analyze every report provided in the `tsan_reports/` folder and separate them into two files: `out.txt` and `nr.txt`.  The former contains all reproducible races while the latter contains reported races that were unable to be reproduced.  To generate TSAN reports in the format needed for Trigger, please use the `tsanOutputParser.py` located in the `scripts/` directory.  This mode allows for easy bulk analysis of multiple TSAN reports.

To run Trigger in interactive mode, start lldb manually by entering the command `lldb target`.  Next, enter the command `command script import trigger.py`.  You should see status information print out to the screen.  Next, in another window, run your benchmarking suite by entering `./benchmark`.  That's it!  From here, Trigger will either pause after verifying a race, or proceed through the test suite without reproducing the race.  If the race is verified, Trigger will return control back to the user so they can manually inspect the state of the program "in the moment."  Please note that this method still requires `target`, `report.txt`, and `args.txt` to be correctly initialized.

### Example
You can find a hands-on example in the `/scripts/trigger/apache-21287` folder of this repository

##### Non-Interactive Mode
```
jason:~/trigger$ ls
trigger  wrapper.sh
jason:~/trigger$ cd trigger && ls && cd ..
args.txt  benchmark.sh  interface.exp  target  trigger.py  tsan_reports
jason:~/trigger$ ./wrapper.sh
Testing tsan_reports/1.txt...
Testing tsan_reports/2.txt...
jason:~/trigger$ ls
nr.txt  trigger  wrapper.sh
jason:~/trigger$ cat nr.txt
join_start_thread (worker.c:1173)                                               
start_threads (worker.c:1083)

join_start_thread (worker.c:1173)                                               
start_threads (worker.c:1083) 
```

##### Interactive Mode
```
jason:~/github/ConAnalysis/scripts/conbreak/mysql-5.7$ ls
args.txt  lldb_out.txt  log.txt  report.txt  target  trigger  wrapper.sh
jason:~/github/ConAnalysis/scripts/conbreak/mysql-5.7$ lldb target
(lldb) target create "target"
Current executable set to 'target' (x86_64).
(lldb) command script import trigger/trigger.py
Setting trigger...
Setting breakpoints...
Configuration done!
Process 20726 launched: '/home/jason/github/ConAnalysis/scripts/conbreak/apache-21287/trigger/target' (x86_64)
target: Could not determine the server's fully qualified domain name, using 172.17.0.21 for ServerName
Process 20726 stopped and restarted: thread 1 received signal: SIGCHLD

// Start ./benchmark from another terminal

1469833176.09 READ:  [20751] Checking 0x7fffc805e538...
1469833176.11 WRITE: [20749] Setting  0x7fffc805e538...
>>>>>>>>>> WRITE: [20749] Found match!
addr=0x7fffc805e538  tid1=20751  tid2=20749
**************************************************************
**************************** HALT ****************************
**************************************************************
Process 20726 stopped
* thread #7: tid = 20749, 0x0000000000427db6 target`remove_entity(h=0x00007fffc4005fd8) + 198 at mod_mem_cache.c:653, name = 'target', stop reason = breakpoint 2.1
    frame #0: 0x0000000000427db6 target`remove_entity(h=0x00007fffc4005fd8) + 198 at mod_mem_cache.c:653
   650          cache_remove(sconf->cache_cache, obj);
   651          sconf->object_cnt--;
   652          sconf->cache_size -= mobj->m_len;
-> 653          obj->cleanup = 1;
   654          ap_log_error(APLOG_MARK, APLOG_INFO, 0, NULL, "gcing a cache entry");
   655      }
   656 
  thread #9: tid = 20751, 0x00000000004271a3 target`decrement_refcount(arg=0x00007fffc805e480) + 275 at mod_mem_cache.c:354, name = 'target', stop reason = breakpoint 1.1
    frame #0: 0x00000000004271a3 target`decrement_refcount(arg=0x00007fffc805e480) + 275 at mod_mem_cache.c:354
   351      /* Cleanup the cache object */
   352  #ifdef USE_ATOMICS
   353      if (!apr_atomic_dec(&obj->refcount)) {
-> 354          if (obj->cleanup) {
   355              cleanup_cache_object(obj);
   356          }
   357      }
(lldb) 
```
