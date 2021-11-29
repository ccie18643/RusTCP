#!/bin/bash
cargo fmt && \
cargo check && \
cargo clippy && \
cargo test
