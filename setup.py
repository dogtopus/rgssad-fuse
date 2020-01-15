#!/usr/bin/env python3
# This file is part of rgssad-fuse.

# rgssad-fuse is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# rgssad-fuse is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with rgssad-fuse.  If not, see <http://www.gnu.org/licenses/>.

from setuptools import setup
import platform

NATIVE_CRYPTO = False

if platform.python_implementation() == 'CPython':
    try:
        from Cython.Build import cythonize
        NATIVE_CRYPTO = True
    except ImportError:
        print('WARNING: Cython not installed, native crypto module could not be '
              'built.')
elif platform.python_implementation() == 'PyPy':
    # Skip native crypto on PyPy since we don't need it.
    NATIVE_CRYPTO = False
else:
    print('WARNING: Unknown Python runtime. Disabling native crypto module.')
    NATIVE_CRYPTO = False

options = dict(
    name='rgssad',
    version='0.3.0',
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
