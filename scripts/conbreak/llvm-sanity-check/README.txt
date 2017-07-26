# A Simple Sanity Check for LLDB

A bug in LLDB's thread state control mechanisms were causing us a bit
of grief.  Run these to make sure everything is ok.

### Installation:
* Follow the README at the project root for instructions on installing LLDB and its dependencies
* Please also make sure to have apache-21287 built as well
* Next, compile the sanity check by typing
```
$ make
```

### Usage:
```
$ lldb test
(lldb) command script import trig[1,2].py
```
Wait five seconds or so (about 5 sets of "Trying again..." messages).  If the program is still running, you're good!  If the program has terminated... :(

### Troubleshooting:
* Try running it a couple more times
* Make sure you're running the sanity check within lldb
* Maybe try reinstalling LLVM/LLDB?
* Good luck...
