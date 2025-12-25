.PHONY: build build-experiments clean test

build:
	./build-macos.sh

build-experiments:
	./experiments/build-experiments.sh

clean:
	rm -rf experiments/out/*

test:
	./tests/preflight.sh --out tests/out/preflight.json
	EJ_INTEGRATION=1 EJ_PREFLIGHT_JSON=tests/out/preflight.json cargo test --manifest-path runner/Cargo.toml
	./tests/ej-smoke.sh
	./tests/ej-app-smoke.sh
