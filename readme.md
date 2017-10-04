# OWL--a system for finding concurrency attacks.

### Install prerequisites:
Firstly you will need python 2.7 and cmake>=3.4.5  before proceed because our project is mainly written in python.<br>
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
### Get and build GCC
```
cd $OWL && mkdir gcc7 && cd gcc7 && export GCC=`pwd`
svn checkout svn://gcc.gnu.org/svn/gcc/trunk $GCC
svn up -r 247494
mkdir build
mkdir install
cd build
# --prefix indicates the path to install/ remember to change it to your absolute path
../configure --enable-languages=c,c++ --disable-bootstrap --enable-checking=no --with-gnu-as --with-gnu-ld --with-ld=/usr/bin/ld.bfd --disable-multilib --prefix=/home/wfan/owl/compilers/gcc7/install/ 
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
make -j48
```
And remember to edit the my.config file to fit your env. Then you can try running syzkaller with
```
cd $GOPATH
./bin/syz-manager -config=my.cfg
```
If error "Could not access KVM kernel module: Permission denied" is reported, you may need to check priviledge setting of /dev/kvm and do chmod.<br><br>

### Build Ktsan Linux Kernel
Ktsan is a kernel built to find races in kernel.
```
cd $OWL/targets/ktsan
make CC='../../compilers/gcc7/install/bin/gcc' -j48
```
This project contains source code of gcc 7.1.0, linux 4.13, go 1.9. <br>
If you want to use newer versions, you can go to their official websites to download.<br>
### Reference
https://github.com/google/syzkaller/blob/master/docs/setup_ubuntu-host_qemu-vm_x86-64-kernel.md <br>
