#!/bin/bash

# Compile example.c to example.o
# -c: compile only, don't link
# -m64: ensure 64-bit (x86-64) architecture

gcc -c -m64 example.c -o example.o

if [ $? -eq 0 ]; then
    echo "Successfully compiled example.c to example.o"
else
    echo "Compilation failed"
    exit 1
fi

