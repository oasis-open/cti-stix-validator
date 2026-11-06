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

7.  Copy the release notes into a new "Release" on `oasis-open/cti-stix-validator` on GitHub, selecting the version tag. Publish the release to trigger `.github/workflows/publish-pypi.yml`. The tag must match `stix2validator/version.py`, with an optional `v` prefix (for example, `v3.3.1` or `3.3.1`).

8.  Watch the **Publish release to PyPI** workflow. It checks out the release tag with both schema submodules, builds the wheel and source distribution, checks their metadata and required STIX schemas, then publishes the validated artifacts using PyPI trusted publishing. Approve the `pypi` environment deployment if reviewers are configured. Fork releases do not run the build or publish jobs. Published prereleases also trigger this workflow, so use a matching Python prerelease version when publishing one.

9.  After the release is up on PyPI, create a temporary virtualenv and install the released version. If installation works fine, try running some samples or unit tests to make sure everything is working as expected.

```bash
virtualenv mktmpenv
source mktmpenv/bin/activate
pip install stix2_validator
./mktmpenv/bin/stix2_validator cti-documentation/examples/example_json/poisonivy.json
deactivate
```

## One-time trusted publishing setup

Before publishing the first release with this workflow:

1. Create a GitHub Actions environment named `pypi` in `oasis-open/cti-stix-validator`. Configure any required reviewers and allow deployment from release tags through the environment's deployment rules.
2. In the existing PyPI project **stix2-validator**, open **Publishing** and add a GitHub trusted publisher with these exact values:

   | Field | Value |
   | --- | --- |
   | Owner | `oasis-open` |
   | Repository | `cti-stix-validator` |
   | Workflow filename | `publish-pypi.yml` |
   | Environment name | `pypi` |

The workflow uses GitHub's OpenID Connect identity (`id-token: write`) in the publish job. No PyPI API token or `.pypirc` secret is needed. The build job has only read access to repository contents; the publish job downloads the checked artifacts without executing repository code.

See [PyPI's trusted publishing documentation](https://docs.pypi.org/trusted-publishers/adding-a-publisher/) for publisher registration details. This workflow must be merged into the OASIS repository before tagging the release; merging it into a fork does not configure the upstream publisher.
