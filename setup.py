#!/usr/bin/env python


from setuptools import setup, find_packages

with open('README.rst') as f:
    readme = f.read()

install_requires = [
    'jsonschema==2.5.1',
    'colorama',
    'six',
    'requests',
    'requests_cache',
    'stix2-patterns>=0.4.1',
    'python-dateutil',
]

setup(
    name='stix2-validator',
    description='APIs and scripts for validating STIX 2.0 documents.',
    url='http://cti-tc.github.io/',
    version='0.4.0',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'stix2_validator = stix2validator.scripts.stix2_validator:main',
        ],
    },
    include_package_data=True,
    install_requires=install_requires,
    long_description=readme,
    keywords="stix stix2 json validation validator stix-validator stix2-validator"
)
