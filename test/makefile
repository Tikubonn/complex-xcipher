
export GCC=gcc
export GDB=gdb
export CFLAGS+=-I$(COMPLEX_XCIPHER_INCLUDE) -L$(COMPLEX_XCIPHER_LIB)

all: bin/test
	$(GDB) bin/test

src/main.o: src/main.c src/test.h
	$(GCC) $(CFLAGS) -c -o src/main.o src/main.c

src/test-complex-xcipher-calc-encrypted-data-size.o: src/test-complex-xcipher-calc-encrypted-data-size.c src/test-complex-xcipher-calc-encrypted-data-size.h src/test.h $(COMPLEX_XCIPHER_INCLUDE)
	$(GCC) $(CFLAGS) -c -o src/test-complex-xcipher-calc-encrypted-data-size.o src/test-complex-xcipher-calc-encrypted-data-size.c

src/test-complex-xcipher-decrypt.o: src/test-complex-xcipher-decrypt.c src/test-complex-xcipher-decrypt.h src/test.h $(COMPLEX_XCIPHER_INCLUDE)
	$(GCC) $(CFLAGS) -c -o src/test-complex-xcipher-decrypt.o src/test-complex-xcipher-decrypt.c

src/test-complex-xcipher-encrypt-into.o: src/test-complex-xcipher-encrypt-into.c src/test-complex-xcipher-encrypt-into.h src/test.h $(COMPLEX_XCIPHER_INCLUDE)
	$(GCC) $(CFLAGS) -c -o src/test-complex-xcipher-encrypt-into.o src/test-complex-xcipher-encrypt-into.c

src/test-complex-xcipher-encrypt.o: src/test-complex-xcipher-encrypt.c src/test-complex-xcipher-encrypt.h src/test.h $(COMPLEX_XCIPHER_INCLUDE)
	$(GCC) $(CFLAGS) -c -o src/test-complex-xcipher-encrypt.o src/test-complex-xcipher-encrypt.c

bin:
	mkdir -p bin

bin/test: src/main.o src/test-complex-xcipher-calc-encrypted-data-size.o src/test-complex-xcipher-decrypt.o src/test-complex-xcipher-encrypt-into.o src/test-complex-xcipher-encrypt.o $(COMPLEX_XCIPHER_INCLUDE) $(COMPLEX_XCIPHER_LIB) | bin
	$(GCC) $(CFLAGS) -o bin/test src/main.o src/test-complex-xcipher-calc-encrypted-data-size.o src/test-complex-xcipher-decrypt.o src/test-complex-xcipher-encrypt-into.o src/test-complex-xcipher-encrypt.o -lcomplexxcipher
