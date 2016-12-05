import unittest
import copy
import json
from . import ValidatorTest
from .. import validate_string

VALID_OBSERVED_DATA_DEFINITION = """
{
  "type": "observed-data",
  "id": "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
  "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
  "created": "2016-04-06T19:58:16Z",
  "modified": "2016-04-06T19:58:16Z",
  "version": 1,
  "first_observed": "2015-12-21T19:00:00Z",
  "last_observed": "2015-12-21T19:00:00Z",
  "number_observed": 50,
  "objects": {
    "0": {
      "type": "file",
      "name": "foo.zip",
      "hashes": {
        "MD5": "B365B9A80A06906FC9B400C06C33FF43"
      },
      "mime_type": "application/zip",
      "extensions": {
        "archive-ext": {
          "contains_refs": [
            "0",
            "1",
            "2"
          ],
          "version": "5.0"
        }
      }
    }
  },
  "granular_markings": [
    {
      "marking_ref": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
      "selectors": [ "objects.0.type" ]
    }
  ]
}
"""


class ObservedDataTestCases(ValidatorTest):
    valid_observed_data = json.loads(VALID_OBSERVED_DATA_DEFINITION)

    def test_wellformed_observed_data(self):
        results = validate_string(VALID_OBSERVED_DATA_DEFINITION, self.options)
        self.assertTrue(results.is_valid)

    def test_number_observed(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['number_observed'] = -1
        observed_data = json.dumps(observed_data)
        self.assertFalseWithOptions(observed_data)

    def test_selector_invalid_property(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['granular_markings'][0]['selectors'][0] = "foobar"
        observed_data = json.dumps(observed_data)
        self.assertFalseWithOptions(observed_data)

    def test_selector_invalid_index(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['granular_markings'][0]['selectors'] = [
          "objects.0.extensions.archive-ext.contains_refs.[5]"
        ]
        observed_data = json.dumps(observed_data)
        self.assertFalseWithOptions(observed_data)

    def test_selector_invalid_list(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['granular_markings'][0]['selectors'] = [
          "objects.[0].extensions"
        ]
        observed_data = json.dumps(observed_data)
        self.assertFalseWithOptions(observed_data)

    def test_selector_invalid_property2(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['granular_markings'][0]['selectors'] = [
          "objects.[0].extensions.archive-ext.contains_refs.[0].type"
        ]
        observed_data = json.dumps(observed_data)
        self.assertFalseWithOptions(observed_data)


if __name__ == "__main__":
    unittest.main()
