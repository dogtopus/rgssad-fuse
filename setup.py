#!/usr/bin/env python3
from setuptools import setup

NATIVE_CRYPTO = False

try:
    from Cython.Build import cythonize
    NATIVE_CRYPTO = True
except ImportError:
    print('WARNING: Cython not installed, native crypto module could not be '
          'built.')

options = dict(
    name='rgssad',
    version='0.2',
    description='RGSSAD library',
    author='dogtopus',
    packages=['rgssad'],
    scripts=['scripts/rgssad-fuse'],
    install_requires=['llfuse']
)

if NATIVE_CRYPTO:
    try:
        options['ext_modules'] = cythonize('rgssad/*.pyx')
    except Cython.Compiler.Errors.CompileError:
        print('WARNING: Cythonize failed. Native modules will not work.')

try:
    setup(**options)
except BuildFailed:
    print('WARNING: Something went wrong during the setup process, trying '
          'again without building the native crypto module.')
    del options['ext_modules']
    setup(**options)
