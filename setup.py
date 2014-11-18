#!/usr/bin/env python

from setuptools import setup, find_packages

setup(name='hubzilla',
      version='0.1',
      description='Middleware to transfer GitHub activities on read only' +
      ' repositories into Bugzilla bug reports automatically',
      author='Bartek Rutkowski',
      author_email='robak@FreeBSD.org',
      license='BeerWare',
      url='https://github.com/bartekrutkowski/hubzilla',
      packages=find_packages(),
      entry_points={
          'console_scripts': ['hubzilla=hubzilla:main', ]
      },
      install_requires=[
          'Flask==0.10.1',
          'configparser==3.3.0r2',
          'python-bugzilla==1.1.0'],
      )
