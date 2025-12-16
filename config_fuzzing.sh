#!/bin/bash

# 0. prepare variables
# TODO: replace with your fuzzing driver name
DRIVER_NAME="fuzz_regexp"
DRIVER_FILE="./fuzz/${DRIVER_NAME}.cpp"
DRIVER_EXECUTABLE="fuzz/${DRIVER_NAME}"
# TODO: replace with your corpus folder
CORPUS_DIR="fuzz/corpus_regexp/"
# TODO: modify fuzz flags as needed
SOURCE_FUZZ_FLAGS="-fsanitize=address,fuzzer-no-link"
DRIVER_FUZZ_FLAGS="-fsanitize=fuzzer,address"

# # 1. compile target project source
# mkdir -p build
# # rm -rf build/*
# cd build
# cmake ../libxml2 \
#   -DBUILD_SHARED_LIBS=OFF \
#   -DCMAKE_C_COMPILER=clang \
#   -DCMAKE_CXX_COMPILER=clang++ \
#   -DCMAKE_CXX_FLAGS="-g -O1 ${SOURCE_FUZZ_FLAGS}" \
#   -DCMAKE_C_FLAGS="-g -O1 ${SOURCE_FUZZ_FLAGS}"
# make "-j$( nproc )"
# cd ../

# 2. compile fuzzing driver
clang++ -g -O2 $DRIVER_FUZZ_FLAGS \
  $DRIVER_FILE \
  -I./libxml2/include \
  -I./build \
  ./build/libxml2.a \
  -o $DRIVER_EXECUTABLE

# 3. running fuzzing driver 
# TODO: modify the parameters as needed
mkdir -p $CORPUS_DIR
# mkdir -p fuzz/crashes
DICT_FILE="./fuzz/xml.dict"
ASAN_OPTIONS=detect_leaks=1 ./${DRIVER_EXECUTABLE} $CORPUS_DIR -max_total_time=60 -dict=${DICT_FILE}