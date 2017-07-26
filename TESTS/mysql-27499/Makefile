# Retain intermediate bitcode files
.PRECIOUS: %.bc

MYSQL=mysql-5.0.33
INCLUDE=$(MYSQL)/include
SQL=$(MYSQL)/sql
REGEX=$(MYSQL)/regex
DIR=$(MYSQL)/libmysqld

# The default target builds the plugin
plugin:
	make -C ../../lib/ConAnal

# create .bc from source
%.bc:
	clang -emit-llvm -O0 -g -c $(MYSQL)/*.cc -I $(INCLUDE) -I $(SQL) -I $(REGEX)
	llvm-link *.bc -o $*.bc

# create human-readable assembly (.ll) from .bc
%.ll: %.bc
	llvm-dis -f $^

# create executable from .bc
%.exe: %.bc
	llc $^
	gcc $*.s -o $*.exe

# create bitcode optimized to keep vars in registers
%.mem2reg: %.bc
	opt -mem2reg $^ -o $*.mem2reg
	mv $*.mem2reg $*.bc

# run printCode on a .bc file
%.printCode: %.bc plugin
	opt -load ../../Debug/lib/P1.so -printCode $*.bc > /dev/null

# run ConAnalysis on a .bc file
%.ConAnalysis: %.bc plugin
	opt -load ../../Debug/lib/ConAnal.so -ConAnalysis $*.bc > /dev/null

# run optLoads on a .bc file, creating a new .bc file
%.optLoads: %.bc plugin
	opt -load ../../Debug/lib/P1.so -optLoads $*.bc -o $*.optLoads
	mv $*.optLoads $*.bc

# run mem2reg then sameRhs on a .c file, creating a .bc file
%.sameRhs: %.bc plugin
	opt -mem2reg $*.bc -o $*.mem2reg
	mv $*.mem2reg $*.bc
	opt -load Debug/lib/P1.so -sameRhs $*.bc -o $*.sameRhs
	mv $*.sameRhs $*.bc

# clean up generated files
clean:
	rm -f *.bc *.exe *.ll *.s
