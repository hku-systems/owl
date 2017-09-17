A system for finding concurrency attacks.

Install prerequisites:
```
sudo apt-get install git subversion flex bison libc6-dev libc6-dev-i386 linux-libc-dev linux-libc-dev:i386 libgmp3-dev libmpfr-dev libmpc-dev build-essential bc
```

Download project:
```
git clone https://github.com/hku-systems/owl.git
cd owl
```

This project contains gcc 8.0 and linux 4.13.
They are the latest versions when we build this project.
If you want to use a newer version, you can use following commands:
```
svn checkout svn://gcc.gnu.org/svn/gcc/trunk $GCC
git clone https://github.com/torvalds/linux.git $KERNEL
```
Or follow instructions on https://github.com/google/syzkaller/blob/master/docs/setup_ubuntu-host_qemu-vm_x86-64-kernel.md
