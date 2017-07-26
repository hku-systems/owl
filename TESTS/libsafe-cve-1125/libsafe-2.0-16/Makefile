# $Name: release2_0-16 $
# $Id: Makefile,v 1.4 2001/07/06 19:52:14 ttsai Exp $


all: libsafe exploits

libsafe::
	cd src; make

debug::
	cd src; make debug

exploits::
	cd exploits; make

doc::
	cd doc; make

clean:
	(cd src && make clean)
	(cd exploits && make clean)
	(cd doc && make clean)

purge:
	(cd src && make purge)
	(cd exploits && make purge)
	(cd doc && make purge)

install:
	cd src; make install
