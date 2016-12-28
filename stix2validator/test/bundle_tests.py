import unittest
import copy
import json
from . import ValidatorTest

VALID_BUNDLE = """
{
  "type": "bundle",
  "id": "bundle--44af6c39-c09b-49c5-9de2-394224b04982",
  "spec_version": "2.0",
  "objects": [
    {
      "type": "identity",
      "id": "identity--8ae20dde-83d4-4218-88fd-41ef0dabf9d1",
      "created": "2016-08-22T14:09:00.123456Z",
      "modified": "2016-08-22T14:09:00.123456Z",
      "name": "mitre.org",
      "identity_class": "organization"
    }
  ]
}
"""


class BundleTestCases(ValidatorTest):
    valid_bundle = json.loads(VALID_BUNDLE)

    def test_wellformed_bundle(self):
        self.assertTrueWithOptions(VALID_BUNDLE)

    def test_bundle_object_categories(self):
        bundle = copy.deepcopy(self.valid_bundle)
        bundle['identities'] = bundle['objects']
        del bundle['objects']
        bundle = json.dumps(bundle)
        self.assertFalseWithOptions(bundle)

    def test_bundle_created(self):
        bundle = copy.deepcopy(self.valid_bundle)
        bundle['created'] = "2016-08-22T14:09:00.123456Z"
        bundle = json.dumps(bundle)
        self.assertFalseWithOptions(bundle)

    def test_bundle_version(self):
        bundle = copy.deepcopy(self.valid_bundle)
        bundle['version'] = 1
        bundle = json.dumps(bundle)
        self.assertFalseWithOptions(bundle)


if __name__ == "__main__":
    unittest.main()
