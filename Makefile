.PHONY: build build-experiments clean test

build:
	./build-macos.sh

build-experiments:
	./experiments/build-experiments.sh

clean:
	rm -rf experiments/out/*

test:
	./scripts/ej-smoke.sh
