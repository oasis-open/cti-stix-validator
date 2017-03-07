import unittest
import copy
import json
from . import ValidatorTest
from .. import validate_string

VALID_RELATIONSHIP = """
{
    "type": "relationship",
    "id": "relationship--44298a74-ba52-4f0c-87a3-1824e67d7fad",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "created": "2016-04-06T20:06:37Z",
    "modified": "2016-04-06T20:06:37Z",
    "source_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "target_ref": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b",
    "relationship_type": "indicates"
}
"""


class RelationshipTestCases(ValidatorTest):
    valid_relationship = json.loads(VALID_RELATIONSHIP)

    def test_wellformed_relationship(self):
        results = validate_string(VALID_RELATIONSHIP, self.options)
        self.assertTrue(results.is_valid)

    def test_relationship_type(self):
        relationship = copy.deepcopy(self.valid_relationship)
        relationship['relationship_type'] = "SOMETHING"
        relationship = json.dumps(relationship)
        results = validate_string(relationship, self.options)
        self.assertEqual(results.is_valid, False)

    def test_source_relationship(self):
        relationship = copy.deepcopy(self.valid_relationship)
        relationship['source_ref'] = "relationship--31b940d4-6f7f-459a-80ea-9c1f17b5891b"
        relationship = json.dumps(relationship)
        results = validate_string(relationship, self.options)
        self.assertEqual(results.is_valid, False)

    def test_source_sighting(self):
        relationship = copy.deepcopy(self.valid_relationship)
        relationship['source_ref'] = "sighting--31b940d4-6f7f-459a-80ea-9c1f17b5891b"
        relationship = json.dumps(relationship)
        results = validate_string(relationship, self.options)
        self.assertEqual(results.is_valid, False)

    def test_target_bundle(self):
        relationship = copy.deepcopy(self.valid_relationship)
        relationship['target_ref'] = "bundle--31b940d4-6f7f-459a-80ea-9c1f17b5891b"
        relationship = json.dumps(relationship)
        results = validate_string(relationship, self.options)
        self.assertEqual(results.is_valid, False)

    def test_target_marking_definition(self):
        relationship = copy.deepcopy(self.valid_relationship)
        relationship['target_ref'] = "marking-definition--31b940d4-6f7f-459a-80ea-9c1f17b5891b"
        relationship = json.dumps(relationship)
        results = validate_string(relationship, self.options)
        self.assertEqual(results.is_valid, False)

    def test_relationship_types_invalid_type(self):
        relationship = copy.deepcopy(self.valid_relationship)
        relationship['source_ref'] = "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b"
        relationship['target_ref'] = "campaign--9c1f891b-459a-6f7f-80ea-31b940d417b5"
        relationship['relationship_type'] = "mitigates"
        relationship = json.dumps(relationship)
        results = validate_string(relationship, self.options)
        self.assertEqual(results.is_valid, False)

        self.check_ignore(relationship, 'relationship-types')

    def test_relationship_types_invalid_source(self):
        relationship = copy.deepcopy(self.valid_relationship)
        relationship['source_ref'] = "identity--b5437038-eb96-4652-88bc-5f94993b7326"
        self.assertFalseWithOptions(json.dumps(relationship))

    def test_relationship_types_invalid_target(self):
        relationship = copy.deepcopy(self.valid_relationship)
        relationship['target_ref'] = "report--af0976b2-e8f3-4646-8026-1cf4d0ce4d8a"
        self.assertFalseWithOptions(json.dumps(relationship))

    def test_relationship_types_valid(self):
        relationship = copy.deepcopy(self.valid_relationship)
        relationship['source_ref'] = "tool--31b940d4-6f7f-459a-80ea-9c1f17b5891b"
        relationship['target_ref'] = "vulnerability--9c1f891b-459a-6f7f-80ea-31b17b5940d4"
        relationship['relationship_type'] = "targets"
        relationship = json.dumps(relationship)
        results = validate_string(relationship, self.options)
        self.assertTrue(results.is_valid)

    def test_relationship_types_common(self):
        relationship = copy.deepcopy(self.valid_relationship)
        relationship['source_ref'] = "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b"
        relationship['target_ref'] = "campaign--9c1f891b-459a-6f7f-80ea-31b940d417b5"
        relationship['relationship_type'] = "related-to"
        relationship = json.dumps(relationship)
        results = validate_string(relationship, self.options)
        self.assertTrue(results.is_valid)

    def test_missing_required(self):
        relationship = copy.deepcopy(self.valid_relationship)
        del relationship['relationship_type']
        self.assertFalseWithOptions(json.dumps(relationship))


if __name__ == "__main__":
    unittest.main()
