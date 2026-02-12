export SOURCE_DATE_EPOCH := 0
export DEBUG-MKIMAGE := 1

build:: lint
	cargo build

release:: lint
	cargo build --release --target x86_64-unknown-linux-musl

lint::
	cargo fmt --all

run:: build
	cd test-vector && .././target/debug/mkimage -f signed.its -k keys2k -r fit
	cd test-vector && .././target/debug/dumpimage -l fit
	shasum test-vector/fit test-vector/targetFit

test::
	cargo test

ci:: lint test