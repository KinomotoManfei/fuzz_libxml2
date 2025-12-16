#!/bin/bash

# this script reports code coverage after running the fuzzing driver

# 0. prepare variables
# TODO: replace with your fuzzing driver name
DRIVER_NAME="fuzz_regexp"
DRIVER_FILE="./fuzz/${DRIVER_NAME}.cpp"
DRIVER_EXECUTABLE="fuzz/${DRIVER_NAME}_cov"
# TODO: replace with your corpus folder
CORPUS_DIR="fuzz/corpus_regexp/"
# TODO: modify fuzz flags as needed
DRIVER_FUZZ_FLAGS="-fsanitize=fuzzer,address"
# TODO: set up coverage report name
REPORT_NAME="cov_html_regexp"
COVERAGE_REPORT_DIR="reports/${REPORT_NAME}"

# # 1. compile target project source with coverage flags
# mkdir -p build-cov
# # rm -rf build-cov/*
# cd build-cov
# cmake ../libxml2 \
#   -DBUILD_SHARED_LIBS=OFF \
#   -DCMAKE_C_COMPILER=clang \
#   -DCMAKE_CXX_COMPILER=clang++ \
#   -DCMAKE_C_FLAGS="-g -O1 -fprofile-instr-generate -fcoverage-mapping"
# make -j$( nproc )
# cd ../

# 2. compile fuzzing driver with coverage flags
clang++ -g -O2 $DRIVER_FUZZ_FLAGS -fprofile-instr-generate -fcoverage-mapping \
  ${DRIVER_FILE} \
  -I./libxml2/include \
  -I./build-cov \
  ./build-cov/libxml2.a \
  -o $DRIVER_EXECUTABLE

# 3. generate coverage report
mkdir -p ./reports
PROFRAW_FILE="./reports/cov.profraw"
rm -f $PROFRAW_FILE
LLVM_PROFILE_FILE=$PROFRAW_FILE ./${DRIVER_EXECUTABLE} $CORPUS_DIR -runs=0
llvm-profdata merge -sparse $PROFRAW_FILE -o reports/cov.profdata
# if you want merge multiple profraw files, use this command:
# llvm-profdata merge -sparse reports/*.profraw -o reports/cov.profdata
llvm-cov show ./$DRIVER_EXECUTABLE \
    -instr-profile=reports/cov.profdata \
    -format=html \
    -output-dir=${COVERAGE_REPORT_DIR}