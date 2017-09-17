# OWL--a system for finding concurrency attacks.

### Install prerequisites:
```
sudo apt-get install git subversion flex bison libc6-dev libc6-dev-i386 linux-libc-dev linux-libc-dev:i386 libgmp3-dev libmpfr-dev libmpc-dev build-essential bc
```

### Download OWL project:

```
git clone https://github.com/hku-systems/owl.git
cd owl
export OWL=`pwd`
```
### Build GCC
```
cd $OWL/targets/gcc7
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
make defconfig
make kvmconfig
cd ..
cp ../cfg_files/linux4.13_syzkaller_cfg .config
make oldconfig
make CC='../gcc7/install/bin/gcc' -j48
```
This project contains gcc 7.1.0($OWL/targets/gcc7) and linux 4.13($OWL/targets/linux)<br>
They are the latest versions when we build this project.<br>
If you want to use a newer version, you can use following commands:<br>
```
svn checkout svn://gcc.gnu.org/svn/gcc/trunk $GCC
git clone https://github.com/torvalds/linux.git $KERNEL
```
Or follow instructions on https://github.com/google/syzkaller/blob/master/docs/setup_ubuntu-host_qemu-vm_x86-64-kernel.md
