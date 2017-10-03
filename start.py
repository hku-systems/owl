#!/usr/bin/env python
import os
if __name__ == '__main__':
	os.system("nohup ./fuzzers/syzkaller/bin/syz-manager -config ./fuzzers/syzkaller/my.cfg &")
