This folder holds all scripts that deal with reports, logs and trace.
1.use inotify to watch the "crashes" folder, remove obvious false positives, copy and save reproduce programs.
2.analyze bug reports: type(null dereference, oob, etc)
3.find corresponding source code and disassemble code
4.static analysis (if applicable)
