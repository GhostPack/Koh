#!/bin/bash

echo "Building Koh BOFs..."

i686-w64-mingw32-gcc -c KohClient.c -o KohClient.x86.o && x86_64-w64-mingw32-gcc -c KohClient.c -o KohClient.x64.o

echo "Build completed!"
