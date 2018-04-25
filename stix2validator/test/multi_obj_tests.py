import copy
import json

from . import ValidatorTest
from .. import validate_parsed_json, validate_string

MULTI_OBJ_JSON = u"""
[
    {
      "type": "attack-pattern",
      "id": "attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
      "created": "2016-02-12T08:17:27.000Z",
      "modified": "2016-02-12T08:17:27.000Z",
      "name": "Spear Phishing",
      "description": "...",
      "external_references": [
        {
          "source_name": "capec",
          "external_id": "CAPEC-463"
        }
      ]
    },

    {
      "type": "identity",
      "id": "identity--2d1c6ab3-5e4e-48ac-a32b-f0c01c2836a8",
      "created": "2014-08-08T15:50:10.983Z",
      "modified": "2014-08-08T15:50:10.983Z",
      "name": "ACME Widget, Inc.",
      "identity_class": "organization"
    }
]
"""


class MultiObjTestCases(ValidatorTest):
    valid_objs = json.loads(MULTI_OBJ_JSON)

    def test_both_valid(self):
        obj_results = validate_string(MULTI_OBJ_JSON)
        self.assertEqual(len(obj_results), 2)
        self.assertTrue(all(r.is_valid for r in obj_results))

    def test_one_valid_one_invalid(self):
        objs = copy.deepcopy(self.valid_objs)
        objs[1]["id"] = objs[1]["id"].replace("identity", "abc")
        obj_results = validate_parsed_json(objs)

        self.assertEqual(len(obj_results), 2)
        self.assertTrue(obj_results[0].is_valid)
        self.assertFalse(obj_results[1].is_valid)
