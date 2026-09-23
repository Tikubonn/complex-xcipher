
export GCC=gcc
export CFLAGS=-Og -g -fPIC -Wall -Iinclude -I$(COMPLEX_XCIPHER_INCLUDE) -L$(COMPLEX_XCIPHER_LIB)
#export COMPLEX_XCIPHER_INCLUDE
#export COMPLEX_XCIPHER_LIB

.PHONY: build
build: bin/test.exe

.PHONY: clean
clean:
	rm -f src/main.o
	rm -f src/test-complex-xcipher-calc-encrypted-data-size.o
	rm -f src/test-complex-xcipher-decrypt.o
	rm -f src/test-complex-xcipher-encrypt-into.o
	rm -f src/test-complex-xcipher-encrypt.o
	rm -f src/test-complex-xcipher-clear.o

.PHONY: run
run: build
	gdb bin/test.exe

src/main.o: src/main.c
	$(GCC) $(CFLAGS) -c -o src/main.o src/main.c

src/test-complex-xcipher-calc-encrypted-data-size.o: src/test-complex-xcipher-calc-encrypted-data-size.c src/test-complex-xcipher-calc-encrypted-data-size.h
	$(GCC) $(CFLAGS) -c -o src/test-complex-xcipher-calc-encrypted-data-size.o src/test-complex-xcipher-calc-encrypted-data-size.c

src/test-complex-xcipher-decrypt.o: src/test-complex-xcipher-decrypt.c src/test-complex-xcipher-decrypt.h
	$(GCC) $(CFLAGS) -c -o src/test-complex-xcipher-decrypt.o src/test-complex-xcipher-decrypt.c

src/test-complex-xcipher-encrypt-into.o: src/test-complex-xcipher-encrypt-into.c src/test-complex-xcipher-encrypt-into.h
	$(GCC) $(CFLAGS) -c -o src/test-complex-xcipher-encrypt-into.o src/test-complex-xcipher-encrypt-into.c

src/test-complex-xcipher-encrypt.o: src/test-complex-xcipher-encrypt.c src/test-complex-xcipher-encrypt.h
	$(GCC) $(CFLAGS) -c -o src/test-complex-xcipher-encrypt.o src/test-complex-xcipher-encrypt.c

src/test-complex-xcipher-clear.o: src/test-complex-xcipher-clear.c src/test-complex-xcipher-clear.h
	$(GCC) $(CFLAGS) -c -o src/test-complex-xcipher-clear.o src/test-complex-xcipher-clear.c

bin:
	mkdir -p bin

bin/complex_xcipher.dll: $(COMPLEX_XCIPHER_LIB)/complex_xcipher.dll | bin
	cp $(COMPLEX_XCIPHER_LIB)/complex_xcipher.dll bin/complex_xcipher.dll

bin/test.exe: src/main.o src/test-complex-xcipher-calc-encrypted-data-size.o src/test-complex-xcipher-decrypt.o src/test-complex-xcipher-encrypt-into.o src/test-complex-xcipher-encrypt.o src/test-complex-xcipher-clear.o bin/complex_xcipher.dll | bin
	$(GCC) $(CFLAGS) -o bin/test.exe src/main.o src/test-complex-xcipher-calc-encrypted-data-size.o src/test-complex-xcipher-decrypt.o src/test-complex-xcipher-encrypt-into.o src/test-complex-xcipher-encrypt.o src/test-complex-xcipher-clear.o -lcomplex_xcipher
