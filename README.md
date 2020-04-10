# Predicate Tracing LLVM Pass

This repository contains a simple LLVM pass to dynamically log predicate counts by instruction type (ICmp or FCmp) and predicate to the path contained in the environment variable PREDICATE_TRACE_LOG_PATH or `/tmp/predicate_trace.json` by default.

## Quickstart

First ensure that you have a recent LLVM and clang installation.  Then,

~~~sh
$ mkdir build
$ cd build
$ CC=clang CXX=clang++ cmake ..
$ make
$ ./run_tests
~~~

