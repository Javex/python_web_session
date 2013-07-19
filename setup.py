from __future__ import unicode_literals, absolute_import
from distutils.core import setup
import os
import re

vfile = open(os.path.join(os.path.dirname(__file__), 'pysess', '__init__.py'))
VERSION = re.match(r".*__version__ = '(.*?)'", vfile.read(), re.S).group(1)
vfile.close()

rfile = open(os.path.join(os.path.dirname(__file__), 'README.md'))
readme = rfile.read()
rfile.close()

setup(
    name='PySess',
    version=VERSION,
    packages=['pysess'],
    license='MIT',
    description="A python web session package to make sessions easy.",
    long_description=readme,
)
