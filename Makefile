LIB := src/opa_bindings/libopabridge.so

.PHONY: all build test fuzz clean

all: build

build:
	cd go && go mod tidy && go build -buildmode=c-shared -o ../$(LIB) .

test: build
	python -m pytest tests/ -v

FUZZ_EXAMPLES ?= 2000
fuzz: build
	PYTHONFAULTHANDLER=1 FUZZ_EXAMPLES=$(FUZZ_EXAMPLES) python -m pytest tests/test_fuzz_bindings.py -m fuzz -v

clean:
	rm -f $(LIB) src/opa_bindings/libopabridge.h
