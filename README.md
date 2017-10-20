# rgssad-fuse

RGSSAD/RGSS3A reader except it has a FUSE interface and various other
insignificant "features" that others don't have.

## Why another RGSSAD tool? There are so many of them already.

This project is built mainly for my personal needs of simplifying the procedure
of poking game scripts (e.g. for porting to linux with [mkxp][1]) and assets
(ripping CG sets, etc.), without the need of extracting everything to the hard
drive (sometimes you won't know where the interested data are stored, without
the ability to search with keywords/thumbnails). Besides that, AFAIK there isn't
any software that mounts a RGSSAD/RGSS3A archive to a directory/volume yet, so
having one would be cool.

## Prerequisites

- *NIX operating system that supports FUSE (Windows support is probably possible
  with [dokan-fuse][2] but it is untested)
- Python 3 (needs to be a relatively recent version that supports `yield from`
  syntax)
- llfuse (not sure about the version, so please use the latest)
- Cython (for building native "crypto" extension for (significantly) faster file
  I/O)

## Installation

Installation can be done either via pip

```
pip install git+https://github.com/dogtopus/rgssad-fuse
```

Or by executing the `setup.py` script (assuming the current working directory is
the project root)

```
pip install llfuse cython
python3 setup.py install
```

## Usage

For invoking FUSE server, use `rgssad-fuse` via the command line. More help is
available via `rgssad-fuse --help`.

It is also possible to use the RGSSAD I/O backend directly as a python library.
Refer to `pydoc rgssad.core` for more information. But please note that the
current API is still pretty user unfriendly and needs work.

[1]: https://github.com/Ancurio/mkxp
[2]: https://dokan-dev.github.io/
