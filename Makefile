.PHONY: build build-experiments clean test

build:
	./build.sh

build-experiments:
	./experiments/build-experiments.sh

clean:
	rm -rf experiments/out/*

test:
	./tests/run.sh --all
