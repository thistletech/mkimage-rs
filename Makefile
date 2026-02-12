export SOURCE_DATE_EPOCH := 0
export DEBUG-MKIMAGE := 1

build:: lint
	cargo build

release:: lint
	argo build --release --target x86_64-unknown-linux-musl

lint::
	cargo fmt --all

run:: lint
	cd test-vector && .././target/debug/mkimage -f signed.its -k keys2k -r fit
	cd test-vector && .././target/debug/dumpimage -l fit

