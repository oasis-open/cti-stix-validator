import copy
import json

import pytest

from . import ValidatorTest
from .. import ValidationError

VALID_BUNDLE = u"""
{
  "type": "bundle",
  "id": "bundle--44af6c39-c09b-49c5-9de2-394224b04982",
  "spec_version": "2.0",
  "objects": [
    {
      "type": "identity",
      "id": "identity--8ae20dde-83d4-4218-88fd-41ef0dabf9d1",
      "created": "2016-08-22T14:09:00.123Z",
      "modified": "2016-08-22T14:09:00.123Z",
      "name": "mitre.org",
      "identity_class": "organization"
    }
  ]
}
"""


class BundleTestCases(ValidatorTest):
    valid_bundle = json.loads(VALID_BUNDLE)

    def test_wellformed_bundle(self):
        self.assertTrueWithOptions(self.valid_bundle)

    def test_bundle_object_categories(self):
        bundle = copy.deepcopy(self.valid_bundle)
        bundle['identities'] = bundle['objects']
        del bundle['objects']
        self.assertFalseWithOptions(bundle)

    def test_bundle_created(self):
        bundle = copy.deepcopy(self.valid_bundle)
        bundle['created'] = "2016-08-22T14:09:00.123456Z"
        self.assertFalseWithOptions(bundle)

    def test_bundle_version(self):
        bundle = copy.deepcopy(self.valid_bundle)
        bundle['version'] = 1
        self.assertFalseWithOptions(bundle)

    def test_bundle_duplicate_ids(self):
        bundle = copy.deepcopy(self.valid_bundle)
        bundle['objects'].append(bundle['objects'][0].copy())
        self.assertFalseWithOptions(bundle)

        bundle['objects'][1]['modified'] = "2017-06-22T14:09:00.123Z"
        self.assertTrueWithOptions(bundle)

    def test_silent_and_verbose(self):
        bundle = json.loads(VALID_BUNDLE)
        with pytest.raises(SystemExit):
            self.assertFalseWithOptions(bundle, silent=True, verbose=True)

    def test_bundle_sdo_missing_type(self):
        bundle = copy.deepcopy(self.valid_bundle)
        del bundle['objects'][0]['type']
        with pytest.raises(ValidationError):
            self.assertFalseWithOptions(bundle)
