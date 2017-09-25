# OWL--a system for finding concurrency attacks.

### Install prerequisites:
Firstly you will need python 2.7 before proceed because our project is mainly written in python. You will also need cmake.<br>
Then run following commands:
```
sudo apt-get install git subversion flex bison libc6-dev libc6-dev-i386 linux-libc-dev linux-libc-dev:i386 libgmp3-dev libmpfr-dev libmpc-dev build-essential bc debootstrap kvm qemu-kvm python-pip
sudo pip install pyinotify
```

### Download OWL project:

```
git clone https://github.com/hku-systems/owl.git
cd owl
export OWL=`pwd`
```
### Build GCC
```
cd $OWL/compilers/gcc7
mkdir build
mkdir install
cd build
../configure --enable-languages=c,c++ --disable-bootstrap --enable-checking=no --with-gnu-as --with-gnu-ld --with-ld=/usr/bin/ld.bfd --disable-multilib --prefix=../install/
make -j48
make install
```
### Build Linux kernel
```
cd $OWL/targets/linux
make CC='../../compilers/gcc7/install/bin/gcc' -j48
```
### Create image
```
cd $OWL/targets/wheezy_image
sh create-image.sh
```
### Set Go environments
For the following two commands you need to add corresponding env(replacing $OWL with real path) in ~/.bashrc file.
```
export GOROOT=$OWL/compilers/goroot
export PATH=$PATH:$GOROOT/bin
export GOPATH=$OWL/fuzzers/syzkaller
```
### Install and config syzkaller
```
go get -u -d github.com/google/syzkaller/...
cd $GOPATH/src/github.com/google/syzkaller/
make
```
And remember to edit the my.config file to fit your env. Then you can try running syzkaller with
```
cd $GOPATH
./bin/syz-manager -config=my.cfg
```
You can also start it by adding "syzkaller" to owl.cfg, and simply type "python start.py".<br>
If error "Could not access KVM kernel module: Permission denied" is reported, you may need to check priviledge setting of /dev/kvm and do chmod.<br><br>
### Build Ktsan Linux Kernel
Ktsan is a kernel built to find races in kernel.
```
cd $OWL/targets/ktsan
make CC='../../compilers/gcc7/install/bin/gcc' -j48
```
This project contains source code of gcc 7.1.0($OWL/targets/gcc7), linux 4.13($OWL/targets/linux), apache 4.2. <br>
They are the latest versions when we build this project.<br>
If you want to use a newer version, for gcc and linux you can use following commands:<br>
```
svn checkout svn://gcc.gnu.org/svn/gcc/trunk $GCC
git clone https://github.com/torvalds/linux.git $KERNEL
```
Or follow instructions on https://github.com/google/syzkaller/blob/master/docs/setup_ubuntu-host_qemu-vm_x86-64-kernel.md <br>
And for other software you can go to following websites:
```
http://httpd.apache.org/download.cgi
```
