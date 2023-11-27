#!/bin/sh
cargo test --all
mkdir -p ts_out/
# mv entity/bindings/* ts_out/
# rmdir entity/bindings
mv member-service/bindings/* ts_out/
rmdir member-service/bindings