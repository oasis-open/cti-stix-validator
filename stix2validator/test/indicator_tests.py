import unittest
import copy
import json
from . import ValidatorTest
from .. import validate_string, validate_instance

VALID_INDICATOR = """
{
    "type": "indicator",
    "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "created_by_ref": "source--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "created": "2016-04-06T20:03:48.000Z",
    "modified": "2016-04-06T20:03:48.000Z",
    "labels": ["malicious-activity"],
    "name": "Poison Ivy Malware",
    "description": "This file is part of Poison Ivy",
    "pattern": "[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']",
    "valid_from": "2016-04-06T20:03:48Z"
}
"""


class IndicatorTestCases(ValidatorTest):
    valid_indicator = json.loads(VALID_INDICATOR)

    def test_wellformed_indicator(self):
        results = validate_string(VALID_INDICATOR, self.options)
        self.assertTrue(results.is_valid)

    def test_modified_before_created(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['modified'] = "2001-04-06T20:03:48Z"
        results = validate_instance(indicator, self.options)
        self.assertEqual(results.is_valid, False)

    def test_custom_property_name_invalid_character(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['my_new_property!'] = "abc123"
        results = validate_instance(indicator, self.options)
        self.assertEqual(results.is_valid, False)

    def test_custom_property_name_short(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['mp'] = "abc123"
        results = validate_instance(indicator, self.options)
        self.assertEqual(results.is_valid, False)

    def test_custom_property_name_long(self):
        indicator = copy.deepcopy(self.valid_indicator)
        long_property_name = 'my_new_property_' * 16
        indicator[long_property_name] = "abc123"
        results = validate_instance(indicator, self.options)
        self.assertEqual(results.is_valid, False)

    def test_empty_list(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['my_new_property'] = []
        results = validate_instance(indicator, self.options)
        self.assertEqual(results.is_valid, False)

    def test_id_type(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['id'] = "something--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
        results = validate_instance(indicator, self.options)
        self.assertEqual(results.is_valid, False)

    def test_reserved_property_confidence(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['confidence'] = "Something"
        results = validate_instance(indicator, self.options)
        self.assertEqual(results.is_valid, False)

    def test_reserved_property_severity(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['severity'] = "Something"
        results = validate_instance(indicator, self.options)
        self.assertEqual(results.is_valid, False)

    def test_reserved_property_action(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['action'] = "Something"
        results = validate_instance(indicator, self.options)
        self.assertEqual(results.is_valid, False)

    def test_reserved_property_usernames(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['usernames'] = "Something"
        results = validate_instance(indicator, self.options)
        self.assertEqual(results.is_valid, False)

    def test_reserved_property_phone_numbers(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['phone_numbers'] = "Something"
        results = validate_instance(indicator, self.options)
        self.assertEqual(results.is_valid, False)

    def test_reserved_property_addresses(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['addresses'] = "Something"
        results = validate_instance(indicator, self.options)
        self.assertEqual(results.is_valid, False)

    def test_reserved_object_type_incident(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['type'] = "incident"
        results = validate_instance(indicator, self.options)
        self.assertEqual(results.is_valid, False)

    def test_reserved_object_type_infrastructure(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['type'] = "infrastructure"
        results = validate_instance(indicator, self.options)
        self.assertEqual(results.is_valid, False)

    def test_vocab_indicator_label(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['labels'] = ["suspicious"]
        results = validate_instance(indicator, self.options)
        self.assertEqual(results.is_valid, False)

        self.check_ignore(indicator, 'indicator-label')

    def test_invalid_pattern(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['pattern'] = """[file:hashes."SHA-256" = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']"""
        self.assertFalseWithOptions(indicator)

    def test_pattern_custom_invalid_format(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['pattern'] = """[ab:yz = 'something']"""
        self.assertFalseWithOptions(indicator)

    def test_pattern_custom_object_noprefix(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['pattern'] = """[foo:name = 'something']"""
        self.assertFalseWithOptions(indicator)

        self.check_ignore(indicator, 'custom-prefix,custom-prefix-lax')
        self.assertFalseWithOptions(indicator, disabled='custom-prefix')

    def test_pattern_custom_object_prefix_strict(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['pattern'] = """[x-x-foo:x_x_name = 'something']"""
        self.assertTrueWithOptions(indicator)

        self.assertFalseWithOptions(indicator, strict_types=True)

    def test_pattern_custom_object_prefix_lax(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['pattern'] = """[x-foo":x_name = 'something']"""
        self.check_ignore(indicator, 'custom-prefix')

    def test_pattern_list_object_property(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['pattern'] = """[windows-registry-key:values[*].data='badstuff']"""
        self.assertTrueWithOptions(indicator)

    def test_pattern_with_escaped_slashes(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['pattern'] = "[windows-registry-key:key LIKE 'HKEY_LOCAL_MACHINE\\\\Foo\\\\Bar%']"
        self.assertTrueWithOptions(indicator)


if __name__ == "__main__":
    unittest.main()
