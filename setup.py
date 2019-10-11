#!/usr/bin/env python

from setuptools import setup

setup(
    name='tsd-file-api',
    version='1.4.0',
    description='A REST API for handling files and data streams',
    author='Leon du Toit',
    author_email='l.c.d.toit@usit.uio.no',
    url='https://bitbucket.usit.uio.no/projects/TSD/repos/tsd-file-api',
    packages=['tsdfileapi'],
    package_data={
        'tsdfileapi': [
            'tests/*.py',
            'tests/*.pem',
            'data/.csv.*',
            'data/.tar.*',
            'data/resume*',
            'data/s*',
            'data/an*',
            'data/tsd/p11/export/*',
            'config/file-api-config.yaml.example',
            'config/file-api.service',
        ]
    },
    scripts=['scripts/fileapi', 'scripts/chowner']
)
