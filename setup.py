#!/usr/bin/env python


from setuptools import setup, find_packages

with open('README.rst') as f:
    readme = f.read()

install_requires = [
    'jsonschema==2.5.1',
    'colorama',
    'six',
]

setup(
    name='stix2-validator',
    description='APIs and scripts for validating STIX 2.0 documents.',
    url='http://stixproject.github.io/',
    version='0.0.1',
    packages=find_packages(),
    scripts=['stix2-validator.py'],
    include_package_data=True,
    install_requires=install_requires,
    long_description=readme,
    keywords="stix stix2 json validation validator stix-validator stix2-validator"
)
