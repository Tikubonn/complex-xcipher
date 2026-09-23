
export GCC=gcc
#export GCC=i686-w64-mingw32-gcc #32bits
export CFLAGS=-O3 -finline-functions -fPIC -Wall

.PHONY: build
build: dst/lib/complex_xcipher.dll dst/lib/complex_xcipher.lib dst/include/complex-xcipher/complex-xcipher.h

.PHONY: clean
clean:
	rm -f src/complex-xcipher.o
	make -C test clean

.PHONY: test
test: build
	make -C test run COMPLEX_XCIPHER_INCLUDE=$(CURDIR)/dst/include COMPLEX_XCIPHER_LIB=$(CURDIR)/dst/lib 

src/complex-xcipher.o: src/complex-xcipher.c src/complex-xcipher.h
	$(GCC) $(CFLAGS) -c -o src/complex-xcipher.o src/complex-xcipher.c

dst/lib:
	mkdir -p dst/lib

dst/lib/complex_xcipher.dll: src/complex-xcipher.o | dst/lib
	$(GCC) $(CFLAGS) -shared -o dst/lib/complex_xcipher.dll src/complex-xcipher.o

dst/lib/complex_xcipher.lib: src/complex-xcipher.o | dst/lib
	ar r dst/lib/complex_xcipher.lib src/complex-xcipher.o

dst/include/complex-xcipher: 
	mkdir -p dst/include/complex-xcipher

dst/include/complex-xcipher/complex-xcipher.h: src/complex-xcipher.h | dst/include/complex-xcipher
	cp src/complex-xcipher.h dst/include/complex-xcipher/complex-xcipher.h
