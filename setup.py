#!/usr/bin/env python

from setuptools import setup

setup(
    name='tsd-file-api',
    version='1.13.0',
    description='A REST API for handling files and json',
    author='Leon du Toit',
    author_email='l.c.d.toit@usit.uio.no',
    url='https://github.com/leondutoit/tsd-file-api',
    packages=['tsdfileapi'],
    package_data={
        'tsdfileapi': [
            'tests/*.py',
            'tests/*.pem',
            'data/.csv.*',
            'data/.tar.*',
            'data/resume*',
            'data/s*',
            'data/r*',
            'data/an*',
            'data/ex*',
            'data/tsd/p11/export/fi*',
            'data/tsd/p11/export/bl*',
            'data/tsd/p11/export/.~lock*',
            'data/tsd/p11/export/data-folder/s*',
            'config/file-api-config.yaml.example',
            'config/file-api.service',
        ]
    },
    scripts=['scripts/generic-chowner']
)
