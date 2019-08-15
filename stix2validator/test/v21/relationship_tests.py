import copy
import json

from . import ValidatorTest
from ... import validate_parsed_json, validate_string

VALID_RELATIONSHIP = u"""
{
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--44298a74-ba52-4f0c-87a3-1824e67d7fad",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "created": "2016-04-06T20:06:37.000Z",
    "modified": "2016-04-06T20:06:37.000Z",
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
        results = validate_parsed_json(relationship, self.options)
        self.assertEqual(results.is_valid, False)

    def test_source_relationship(self):
        relationship = copy.deepcopy(self.valid_relationship)
        relationship['source_ref'] = "relationship--31b940d4-6f7f-459a-80ea-9c1f17b5891b"
        results = validate_parsed_json(relationship, self.options)
        self.assertEqual(results.is_valid, False)
        self.assertEqual(len(results.errors), 1)

    def test_source_sighting(self):
        relationship = copy.deepcopy(self.valid_relationship)
        relationship['source_ref'] = "sighting--31b940d4-6f7f-459a-80ea-9c1f17b5891b"
        results = validate_parsed_json(relationship, self.options)
        self.assertEqual(results.is_valid, False)

    def test_target_bundle(self):
        relationship = copy.deepcopy(self.valid_relationship)
        relationship['target_ref'] = "bundle--31b940d4-6f7f-459a-80ea-9c1f17b5891b"
        results = validate_parsed_json(relationship, self.options)
        self.assertEqual(results.is_valid, False)
        self.assertEqual(len(results.errors), 1)

    def test_target_marking_definition(self):
        relationship = copy.deepcopy(self.valid_relationship)
        relationship['target_ref'] = "marking-definition--31b940d4-6f7f-459a-80ea-9c1f17b5891b"
        results = validate_parsed_json(relationship, self.options)
        self.assertEqual(results.is_valid, False)

    def test_relationship_types_invalid_type(self):
        relationship = copy.deepcopy(self.valid_relationship)
        relationship['source_ref'] = "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b"
        relationship['target_ref'] = "campaign--a2576331-d670-4fb3-8ff3-6fb6b4e698b2"
        relationship['relationship_type'] = "mitigates"
        results = validate_parsed_json(relationship, self.options)
        self.assertEqual(results.is_valid, False)

        self.check_ignore(relationship, 'relationship-types')

    def test_relationship_types_invalid_source(self):
        relationship = copy.deepcopy(self.valid_relationship)
        relationship['source_ref'] = "identity--b5437038-eb96-4652-88bc-5f94993b7326"
        self.assertFalseWithOptions(relationship)

    def test_relationship_types_invalid_target(self):
        relationship = copy.deepcopy(self.valid_relationship)
        relationship['target_ref'] = "report--af0976b2-e8f3-4646-8026-1cf4d0ce4d8a"
        self.assertFalseWithOptions(relationship)

    def test_relationship_types_valid(self):
        relationship = copy.deepcopy(self.valid_relationship)
        relationship['source_ref'] = "tool--31b940d4-6f7f-459a-80ea-9c1f17b5891b"
        relationship['target_ref'] = "vulnerability--280d1c0d-51d1-4ee8-951f-1fb434a38686"
        relationship['relationship_type'] = "targets"
        results = validate_parsed_json(relationship, self.options)
        self.assertTrue(results.is_valid)

    def test_relationship_types_common(self):
        relationship = copy.deepcopy(self.valid_relationship)
        relationship['source_ref'] = "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b"
        relationship['target_ref'] = "campaign--a2576331-d670-4fb3-8ff3-6fb6b4e698b2"
        relationship['relationship_type'] = "related-to"
        results = validate_parsed_json(relationship, self.options)
        self.assertTrue(results.is_valid)

    def test_missing_required(self):
        relationship = copy.deepcopy(self.valid_relationship)
        del relationship['relationship_type']
        self.assertFalseWithOptions(relationship)

    def test_invalid_stop_time(self):
        relationship = copy.deepcopy(self.valid_relationship)
        relationship['start_time'] = "2016-04-06T20:06:37.000Z"
        relationship['stop_time'] = "2016-04-06T20:06:37.000Z"
        self.assertFalseWithOptions(relationship)

        relationship['stop_time'] = "2016-01-01T00:00:00.000Z"
        self.assertFalseWithOptions(relationship)

        relationship['stop_time'] = "2016-05-07T20:06:37.000Z"
        self.assertTrueWithOptions(relationship)
