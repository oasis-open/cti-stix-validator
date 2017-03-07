import unittest
import copy
import json
from . import ValidatorTest
from .. import validate_string

VALID_ATTACK_PATTERN = """
{
  "type": "attack-pattern",
  "id": "attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
  "created": "2016-05-12T08:17:27.000000Z",
  "modified": "2016-05-12T08:17:27.000000Z",
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
        attack_pattern = json.dumps(attack_pattern)
        results = validate_string(attack_pattern, self.options)
        self.assertEqual(results.is_valid, False)

    def test_external_reference_no_external_id(self):
        attack_pattern = copy.deepcopy(self.valid_attack_pattern)
        ext_refs = attack_pattern['external_references']
        del ext_refs[0]['external_id']
        attack_pattern = json.dumps(attack_pattern)
        results = validate_string(attack_pattern, self.options)
        self.assertEqual(results.is_valid, False)

    def test_invalid_property_prefix(self):
        attack_pattern = copy.deepcopy(self.valid_attack_pattern)
        attack_pattern['x-something'] = "some value"
        attack_pattern_string = json.dumps(attack_pattern)
        results = validate_string(attack_pattern_string, self.options)
        self.assertEqual(results.is_valid, False)

        self.assertFalseWithOptions(attack_pattern_string, enabled='custom-property-prefix-lax')

    def test_invalid_property_prefix_lax(self):
        attack_pattern = copy.deepcopy(self.valid_attack_pattern)
        attack_pattern['x_something'] = "some value"
        attack_pattern_string = json.dumps(attack_pattern)
        results = validate_string(attack_pattern_string, self.options)
        self.assertEqual(results.is_valid, False)

        self.assertTrueWithOptions(attack_pattern_string, enabled='custom-property-prefix-lax')
        self.assertFalseWithOptions(attack_pattern_string, disabled='custom-property-prefix-lax')
        self.check_ignore(attack_pattern_string, 'custom-property-prefix')

    def test_valid_property_prefix(self):
        attack_pattern = copy.deepcopy(self.valid_attack_pattern)
        attack_pattern['x_source_something'] = "some value"
        attack_pattern_string = json.dumps(attack_pattern)
        results = validate_string(attack_pattern_string, self.options)
        self.assertTrue(results.is_valid)


if __name__ == "__main__":
    unittest.main()
