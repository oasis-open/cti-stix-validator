#!/usr/bin/env python


from setuptools import find_packages, setup

with open('README.rst') as f:
    readme = f.read()


def get_version():
    with open('stix2validator/version.py') as f:
        for line in f.readlines():
            if line.startswith("__version__"):
                version = line.split()[-1].strip('"')
                return version
        raise AttributeError("Package does not have a __version__")


install_requires = [
    'appdirs',
    'colorama<0.4.2',
    'cpe',
    'jsonschema[format_nongpl]>=3.2.0',
    'python-dateutil',
    'requests',
    'requests_cache',
    'simplejson',
    'six',
    'stix2-patterns>=0.4.1',
]

setup(
    name='stix2-validator',
    version=get_version(),
    description='APIs and scripts for validating STIX 2.x documents.',
    long_description=readme,
    long_description_content_type='text/x-rst',
    url="https://github.com/oasis-open/cti-stix-validator",
    author='OASIS Cyber Threat Intelligence Technical Committee',
    author_email='cti-users@lists.oasis-open.org',
    maintainer='Chris Lenk',
    maintainer_email='clenk@mitre.org',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Topic :: Security',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
    keywords="stix stix2 json validation validator stix-validator stix2-validator",
    packages=find_packages(exclude=['*.test.*']),
    install_requires=install_requires,
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'stix2_validator = stix2validator.scripts.stix2_validator:main',
        ],
    },
)
