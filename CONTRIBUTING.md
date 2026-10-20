# Contributing

Small, reviewable changes are welcome. Please include a focused regression test for parser, policy, or report behavior and keep the CLI's documented scope accurate.

Build and test with CMake 3.20+ and a C++20 compiler:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The test suite is dependency-free. Do not add host-mutating tests or tests that install seccomp policies on the developer machine. Keep sample profiles synthetic and free of environment-specific paths.
