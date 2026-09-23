
.PHONY: build
build: dst/include dst/lib dst/bin

.PHONY: clean
clean:
	make -C lib clean
	make -C app clean

.PHONY: test
test:
	make -C lib test
	make -C app test COMPLEX_XCIPHER_INCLUDE=$(CURDIR)/lib/dst/include COMPLEX_XCIPHER_LIB=$(CURDIR)/lib/dst/lib

dst/include:
	make -C lib build
	cp -r lib/dst/include dst/include

dst/lib:
	make -C lib build
	cp -r lib/dst/lib dst/lib

dst/bin:
	make -C app build COMPLEX_XCIPHER_INCLUDE=$(CURDIR)/lib/dst/include COMPLEX_XCIPHER_LIB=$(CURDIR)/lib/dst/lib
	cp -r app/bin dst/bin
