import copy
import json

from . import ValidatorTest
from ... import validate_parsed_json, validate_string

VALID_ATTACK_PATTERN = u"""
{
  "type": "attack-pattern",
  "spec_version": "2.1",
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
}
"""


class AttackPatternTestCases(ValidatorTest):
    valid_attack_pattern = json.loads(VALID_ATTACK_PATTERN)

    def test_wellformed_attack_pattern(self):
        results = validate_string(VALID_ATTACK_PATTERN, self.options)
        self.assertTrue(results.is_valid)

    def test_valid_capec_id(self):
        attack_pattern = copy.deepcopy(self.valid_attack_pattern)
        ext_refs = attack_pattern['external_references']
        ext_refs[0]['external_id'] = "CAPEC-abc"
        results = validate_parsed_json(attack_pattern, self.options)
        self.assertEqual(results.is_valid, False)

    def test_external_reference_no_external_id(self):
        attack_pattern = copy.deepcopy(self.valid_attack_pattern)
        ext_refs = attack_pattern['external_references']
        del ext_refs[0]['external_id']
        results = validate_parsed_json(attack_pattern, self.options)
        self.assertEqual(results.is_valid, False)

    def test_invalid_property_prefix(self):
        attack_pattern = copy.deepcopy(self.valid_attack_pattern)
        attack_pattern['x-something'] = "some value"
        self.assertFalseWithOptions(attack_pattern)

        self.assertFalseWithOptions(attack_pattern, enabled='custom-prefix-lax')
        self.assertFalseWithOptions(attack_pattern, disabled='extensions-use,custom-prefix')

    def test_invalid_property_prefix_lax(self):
        attack_pattern = copy.deepcopy(self.valid_attack_pattern)
        attack_pattern['x_something'] = "some value"
        self.assertFalseWithOptions(attack_pattern)

        self.assertTrueWithOptions(attack_pattern, enabled='custom-prefix-lax')
        self.assertFalseWithOptions(attack_pattern, disabled='custom-prefix-lax')
        self.assertFalseWithOptions(attack_pattern, disabled='custom-prefix')
        self.assertFalseWithOptions(attack_pattern, disabled='extensions-use,custom-prefix-lax')
        self.assertTrueWithOptions(attack_pattern, disabled='extensions-use,custom-prefix')

    def test_valid_property_prefix(self):
        attack_pattern = copy.deepcopy(self.valid_attack_pattern)
        attack_pattern['x_source_something'] = "some value"

        self.assertTrueWithOptions(attack_pattern, enabled='custom-prefix')
        self.assertTrueWithOptions(attack_pattern, disabled='extensions-use')

    def test_custom_property_without_extension(self):
        attack_pattern = copy.deepcopy(self.valid_attack_pattern)
        attack_pattern['something'] = "some value"

        self.assertFalseWithOptions(attack_pattern)
        self.assertFalseWithOptions(attack_pattern, strict_properties=True)
        self.assertFalseWithOptions(attack_pattern, strict_properties=True, disabled='extensions-use')
        self.assertFalseWithOptions(attack_pattern, disabled='extensions-use')
        self.assertTrueWithOptions(attack_pattern, disabled='extensions-use,custom-prefix,custom-prefix-lax')
        self.assertFalseWithOptions(attack_pattern, strict_properties=True, disabled='extensions-use,custom-prefix,custom-prefix-lax')

    def test_custom_property_with_extension(self):
        attack_pattern = copy.deepcopy(self.valid_attack_pattern)
        attack_pattern['something'] = "some value"
        attack_pattern['extensions'] = {
            "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
                "extension_type": "property-extension",
                "rank": 5,
                "toxicity": 8
            }
        }

        self.assertFalseWithOptions(attack_pattern)
        self.assertFalseWithOptions(attack_pattern, strict_properties=True)
        self.assertFalseWithOptions(attack_pattern, strict_properties=True, disabled='extensions-use')

        del attack_pattern['something']
        self.assertTrueWithOptions(attack_pattern, strict_properties=True)

    def test_custom_toplevel_property_with_extension(self):
        attack_pattern = copy.deepcopy(self.valid_attack_pattern)
        attack_pattern['something'] = "some value"
        attack_pattern['rank'] = 5
        attack_pattern['toxicity'] = 8
        attack_pattern['extensions'] = {
            "extension-definition--a932fcc6-e032-176c-826f-cb970a5a1fff": {
                "extension_type": "toplevel-property-extension",
            }
        }

        self.assertTrueWithOptions(attack_pattern)
        self.assertFalseWithOptions(attack_pattern, strict_properties=True)
        self.assertFalseWithOptions(attack_pattern, strict_properties=True, disabled='extensions-use')
        self.assertFalseWithOptions(attack_pattern, disabled='extensions-use')
        self.assertTrueWithOptions(attack_pattern, disabled='extensions-use,custom-prefix,custom-prefix-lax')
        self.assertFalseWithOptions(attack_pattern, strict_properties=True, disabled='extensions-use,custom-prefix,custom-prefix-lax')

    def test_invalid_timestamp(self):
        attack_pattern = copy.deepcopy(self.valid_attack_pattern)
        attack_pattern['modified'] = "2016-13-12T08:17:27.000Z"
        self.assertFalseWithOptions(attack_pattern)

        attack_pattern['modified'] = "2016-03-42T08:17:27.000Z"
        self.assertFalseWithOptions(attack_pattern)

        attack_pattern['modified'] = "2016-03-00T08:17:27.000Z"
        self.assertFalseWithOptions(attack_pattern)

        attack_pattern['modified'] = "2016-03-12T99:17:27.000Z"
        self.assertFalseWithOptions(attack_pattern)

        attack_pattern['modified'] = "2016-03-12T08:99:27.000Z"
        self.assertFalseWithOptions(attack_pattern)

        attack_pattern['modified'] = "2016-11-31T08:17:27.000Z"
        self.assertFalseWithOptions(attack_pattern)

        attack_pattern['modified'] = "2017-02-29T08:17:27.000Z"
        self.assertFalseWithOptions(attack_pattern)

        attack_pattern['created'] = "2016-02-29T08:17:27.000036Z"
        self.assertFalseWithOptions(attack_pattern)

        attack_pattern['modified'] = "2016-02-29T08:17:27.001Z"
        self.assertTrueWithOptions(attack_pattern)
