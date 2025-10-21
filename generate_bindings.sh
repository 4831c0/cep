#!/bin/sh

git apply dart.diff
cargo build --release \
  && cargo run --bin uniffi-bindgen generate --library target/release/libcep.so \
    --language kotlin \
    --language python \
    --out-dir out \
  && uniffi-bindgen-go src/cep.udl -o out
git apply dart.diff -R
git checkout Cargo.lock
