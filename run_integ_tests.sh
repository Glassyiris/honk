#!/bin/bash
set -e

# We need to change to the directory to pick up the cargo config
(cd crates/integ && cargo +1.90.0 nextest run)
