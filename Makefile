.PHONY: build clean test

build:
	./build-macos.sh

clean:
	rm -rf experiments/out/*

test:
	./scripts/ej-smoke.sh
