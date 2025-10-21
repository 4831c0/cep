#!/bin/sh

cargo build --release \
  && cargo run --bin uniffi-bindgen generate --library target/release/libcep.so \
    --language kotlin \
    --language python \
    --out-dir out \
  && uniffi-bindgen-go src/cep.udl -o out