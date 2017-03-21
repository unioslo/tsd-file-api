from distutils.core import setup

setup(
    name='tsd-file-api',
    version='0.1.0',
    description='A REST API for handling files and data streams',
    author='Leon du Toit',
    author_email='l.c.d.toit@usit.uio.no',
    url='https://bitbucket.usit.uio.no/projects/TSD/repos/tsd-file-api',
    packages=['tsdfileapi'],
    package_data={
        'tsdfileapi': [
            'tests/*.py'
        ]
    }
)
