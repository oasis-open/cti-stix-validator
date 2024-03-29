# Releasing a new version of stix2_validator

These steps will upgrade the 'stix-validator' package to version
3.1.3. Substitute values as necessary.

0. Follow the directions in docs/contributing.rst to ensure that your environment is correct. Especially make note of the git submodule steps.

1.  Make sure that the README file is up-to-date and is consistent with any similar documentation (ReadTheDocs).

2.  Make sure your git working directory is clean (no unstaged changes, or un-committed added/removed files), that the code is up-to-date, and that the code is passing all tests (run with nose, pytest, and/or tox, etc.).

```bash
git status
git pull
tox -r
```

3.  Update the CHANGELOG file with changes since the last release. To help, you can run one of the following:

```bash
git diff <old tag>..master
git log <old tag>..master
gitk <old tag>..master
```

```bash
git add CHANGELOG
```


4.  Run bumpversion patch, bumpversion minor, or bumpversion major (as appropriate).

5.  Create a single commit with all of these changes. This helps improve clarity down the road. Push this commit to GitHub.

```bash
git commit -m \"Bump version to 3.1.3\"
git push origin master
```

Ensure the new commit passes in CI. If the build on CI fails, make any
changes necessary for it to pass, then commit and push them before
continuing.

6.  Once Github Actions shows a passing build for the master branch, create a tag for the new release. Push the tag to GitHub as well. (bumpversion may create the tag locally.)

```bash
git tag -a "v3.1.3" -m "Version 3.1.3"
git push origin --tags
```

7.  Copy the release notes into a new "Release" on GitHub. Don't forget to publish the "Release".

8.  Make sure your release directory is "clean".

```bash
git clean -x -f -d
```

9.  Build and publish the new package. This method requires that you have a .pypirc file containing your PyPI credentials, and that your account has appropriate permissions on the PyPI project. See [the Python documentation](http://docs.python.org/2/distutils/packageindex.html#the-pypirc-file) for more information.

```bash
python3 setup.py sdist bdist_wheel
twine upload dist/\*
```

If the filename does not end with -py2.py3-none-any.whl, it is not
correctly configured as a "Universal" wheel.

10. After the release is up on PyPI, create a temporary virtualenv and was downloaded and installed. If installation works fine, try running some samples or unit tests to make sure everything is working as expected.

```bash
virtualenv mktmpenv
source mktmpenv/bin/activate
pip install stix2_validator
./mktmpenv/bin/stix2_validator cti-documentation/examples/example_json/poisonivy.json
deactivate
```
