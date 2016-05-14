#!/bin/bash
cd `dirname $0`
clang-format -i --style=File sources/*.h sources/*.cpp test/*.cpp
