# Retain intermediate bitcode files
.PRECIOUS: %.bc

# The default target builds the plugin
plugin:
	make -C ../../lib/ConAnal

# create .bc from source
%.bc:	%.c
	clang -emit-llvm -O0 -g -c $*.c -o $*.bc

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
	opt -load Debug/lib/P1.so -printCode $*.bc > /dev/null

# run ConAnalysis on a .bc file
%.ConAnalysis: %.bc plugin
	opt -load ../../Debug/lib/ConAnal.so -ConAnalysis $*.bc > /dev/null

# clean up generated files
clean:
	make -C ../../lib/ConAnal clean
	rm -f *.bc *.exe *.ll *.s
