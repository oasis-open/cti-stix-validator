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
    'colorama',
    'cpe',
    'jsonschema[format-nongpl]>=4.20.0',
    'python-dateutil',
    'requests',
    'simplejson',
    'stix2-patterns>=2.1.2',
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
    python_requires=">=3.10",
    maintainer='Chris Lenk',
    maintainer_email='clenk@mitre.org',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Topic :: Security',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        'Programming Language :: Python :: 3.14'
    ],
    keywords="stix stix2 json validation validator stix-validator stix2-validator",
    project_urls={
        'Documentation': 'https://stix2-validator.readthedocs.io/',
        'Source Code': 'https://github.com/oasis-open/cti-stix-validator/',
        'Bug Tracker': 'https://github.com/oasis-open/cti-stix-validator/issues/',
    },
    packages=find_packages(exclude=['*.test.*']),
    install_requires=install_requires,
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'stix2_validator = stix2validator.scripts.stix2_validator:main',
        ],
    },
    extras_require={
        'dev': [
            'bumpversion',
            'pre-commit',
            'requests',
        ],
        'test': [
            'coverage',
            'pytest',
            'pytest-cov',
            'tox',
        ],
        'docs': [
            'sphinx',
            'sphinx-prompt',
        ],
    },
)
