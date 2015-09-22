#!/bin/sh

# export AW_CLONE_PATH=../..

test -d aw-make || git clone git@github.com:afterwise/aw-make.git || exit 1
make -f aw-make/bas.mk $* || exit 1
if [ "$*" == "distclean" ]; then rm -rf aw-make; fi

