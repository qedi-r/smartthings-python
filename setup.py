#!/usr/bin/env python
# coding: utf8

from setuptools import setup, find_packages

# Get long_description from README
import os
here = os.path.dirname(os.path.abspath(__file__))
f = open(os.path.join(here, 'README.rst'))
long_description = f.read().strip()
f.close()

setup(
    name='smartthings',
    version='0.1.1',
    url='https://github.com/qedi-r/smartthings-python',
    license='MIT',
    author='Ryan Bianchi',
    author_email='github@infornography.ca',
    description='Use SmartThings API with Python.',
    long_description=long_description,
    packages = find_packages(),
    install_requires=[],
    platforms='any',
    classifiers=[
        'Topic :: System :: Networking',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
    ]
)
