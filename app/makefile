
export GCC=gcc
export CFLAGS=-O3 -finline-functions -fPIC -Wall -I$(COMPLEX_XCIPHER_INCLUDE) -L$(COMPLEX_XCIPHER_LIB)
#export COMPLEX_XCIPHER_INCLUDE=
#export COMPLEX_XCIPHER_LIB=

.PHONY: build
build: bin/complex-xcipher.exe

.PHONY: clean
clean:
	rm -f src/main.o

.PHONY: test
test: build
	make -C test run COMPLEX_XCIPHER_BIN=$(CURDIR)/bin

src/main.o: src/main.c
	$(GCC) $(CFLAGS) -c -o src/main.o src/main.c

bin:
	mkdir -p bin

bin/complex_xcipher.dll: $(COMPLEX_XCIPHER_LIB)/complex_xcipher.dll | bin
	cp $(COMPLEX_XCIPHER_LIB)/complex_xcipher.dll bin/complex_xcipher.dll

bin/complex-xcipher.exe: src/main.o bin/complex_xcipher.dll | bin
	$(GCC) $(CFLAGS) -o bin/complex-xcipher.exe src/main.o -lcomplex_xcipher
