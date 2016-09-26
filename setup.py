#!/usr/bin/env python3
from setuptools import setup
from Cython.Build import cythonize

setup(name='rgssad',
      version='0.1',
      description='RGSSAD library',
      author='dogtopus',
      packages=['rgssad'],
      scripts=['scripts/rgssad-fuse'],
      ext_modules=cythonize('rgssad/*.pyx'),
      install_requires=['llfuse']
)
