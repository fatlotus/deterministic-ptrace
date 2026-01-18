#!/bin/bash
set -e
echo "Hello from bash"
# The integration test runs from the root of the project.
# We want to cd into test_dir
cd test_dir
echo "Current directory: $(pwd)"
# Try to run one of our built binaries. 
$CARGO_BIN_EXE_thread_clock_test
echo "done"
