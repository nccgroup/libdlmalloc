#!/usr/bin/env python
#
# This file is part of libdlmalloc.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>

from distutils.core import setup

setup(name='dlmalloc',
      version='0.1',
      description='gdb python library for examining the dlmalloc heap',
      author='NCC Group',
      url='https://github.com/nccgroup/libdlmalloc',
      license="MIT",
      keywords="dlmalloc gdb python",
      py_modules=['libdlmalloc-2.8', 'printutils', 'prettyprinters']
     )
