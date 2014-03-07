from __future__ import unicode_literals, absolute_import
from setuptools import setup, Command
import os
import re
import subprocess
import sys


class PyTest(Command):
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        errno = subprocess.call([sys.executable, 'runtests.py'])
        raise SystemExit(errno)


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
    cmdclass={'test': PyTest},
)
