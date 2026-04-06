
export GCC=gcc
export CFLAGS=-Wall
export CFLAGS_DEBUG=-g -Og
export CFLAGS_RELEASE=-O3 -finline-functions

.PHONY: default
default:
	make debug 

.PHONY: debug
debug:
	make build CFLAGS="$(CFLAGS) $(CFLAGS_DEBUG)"

.PHONY: release
release:
	make build CFLAGS="$(CFLAGS) $(CFLAGS_RELEASE)"

.PHONY: build
build: dist/include/complex-xcipher/complex-xcipher.h dist/lib/libcomplexxcipher.so dist/lib/libcomplexxcipher.a dist/bin/complex-xcipher.exe

.PHONY: clean
clean:
	rm -f src/complex-xcipher.o

.PHONY: test
test: 
	make test-lib test-app

.PHONY: test-lib
test-lib: debug
	make -C test/lib COMPLEX_XCIPHER_INCLUDE=$(CURDIR)/dist/include COMPLEX_XCIPHER_LIB=$(CURDIR)/dist/lib

.PHONY: test-app
test-app: debug
	pytest -v --executable $(CURDIR)/dist/bin/complex-xcipher.exe test/app

.PHONY: setup
	pip install -y pytest

src/complex-xcipher.o: src/complex-xcipher.c src/complex-xcipher.h
	$(GCC) $(CFLAGS) -c -o src/complex-xcipher.o src/complex-xcipher.c

dist/include/complex-xcipher:
	mkdir -p dist/include/complex-xcipher

dist/include/complex-xcipher/complex-xcipher.h: src/complex-xcipher.h | dist/include/complex-xcipher
	cp src/complex-xcipher.h dist/include/complex-xcipher/

dist/lib:
	mkdir -p dist/lib

dist/lib/libcomplexxcipher.so: src/complex-xcipher.o | dist/lib
	$(GCC) $(CFLAGS) -shared -o dist/lib/libcomplexxcipher.so src/complex-xcipher.o

dist/lib/libcomplexxcipher.a: src/complex-xcipher.o | dist/lib
	ar r dist/lib/libcomplexxcipher.a src/complex-xcipher.o

dist/bin:
	mkdir -p dist/bin

dist/bin/complex-xcipher.exe: src/main.c dist/lib/libcomplexxcipher.a | dist/bin
	$(GCC) $(CFLAGS) -o dist/bin/complex-xcipher.exe src/main.c -Ldist/lib -lcomplexxcipher
