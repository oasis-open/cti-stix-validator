#!/usr/bin/env python3

from pathlib import Path
import tarfile
import zipfile


REQUIRED_FILES = (
    'stix2validator/schemas-2.0/schemas/common/'
    'cyber-observable-core.json',
    'stix2validator/schemas-2.1/schemas/common/'
    'cyber-observable-core.json',
)


def check_members(artifact, members):
    missing = [
        required
        for required in REQUIRED_FILES
        if not any(member.endswith(required) for member in members)
    ]

    if missing:
        raise SystemExit(
            f'{artifact}: required STIX schemas are missing:\n  '
            + '\n  '.join(missing)
        )


def check_wheel(path):
    with zipfile.ZipFile(path) as archive:
        check_members(path, archive.namelist())


def check_sdist(path):
    with tarfile.open(path, 'r:gz') as archive:
        check_members(path, archive.getnames())


def main():
    dist = Path('dist')
    wheels = list(dist.glob('*.whl'))
    sdists = list(dist.glob('*.tar.gz'))

    if not wheels or not sdists:
        raise SystemExit('Expected both a wheel and a source distribution')

    for artifact in wheels:
        check_wheel(artifact)

    for artifact in sdists:
        check_sdist(artifact)

    print('Distribution contains the required STIX 2.0 and 2.1 schemas.')


if __name__ == '__main__':
    main()
