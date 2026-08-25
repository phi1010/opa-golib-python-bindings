LIB := src/opa_bindings/libopabridge.so

.PHONY: all build test clean

all: build

build:
	cd go && go mod tidy && go build -buildmode=c-shared -o ../$(LIB) .

test: build
	python -m pytest tests/ -v

clean:
	rm -f $(LIB) src/opa_bindings/libopabridge.h
