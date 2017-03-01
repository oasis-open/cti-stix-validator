import unittest
import copy
import json
from . import ValidatorTest
from .. import validate_string

VALID_MARKING_DEFINITION = """
{
  "type": "marking-definition",
  "id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
  "created": "2016-08-01T00:00:00Z",
  "definition_type": "tlp",
  "definition": {
    "tlp": "green"
  }
}
"""


class MarkingDefinitionTestCases(ValidatorTest):
    valid_marking_definition = json.loads(VALID_MARKING_DEFINITION)

    def test_wellformed_marking_definition(self):
        results = validate_string(VALID_MARKING_DEFINITION, self.options)
        self.assertTrue(results.is_valid)

    def test_vocab_marking_definition_label(self):
        marking_definition = copy.deepcopy(self.valid_marking_definition)
        marking_definition['definition_type'] = "something"
        marking_definition = json.dumps(marking_definition)
        results = validate_string(marking_definition, self.options)
        self.assertEqual(results.is_valid, False)

        self.check_ignore(marking_definition, 'marking-definition-type')

    def test_lax_option(self):
        marking_definition = copy.deepcopy(self.valid_marking_definition)
        marking_definition['definition_type'] = "something"
        marking_definition = json.dumps(marking_definition)
        self.assertFalseWithOptions(marking_definition)
        self.assertTrueWithOptions(marking_definition, strict=False)

    def test_object_marking_ref_circular_ref(self):
        marking_definition = copy.deepcopy(self.valid_marking_definition)
        marking_definition['object_marking_refs'] = ["marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"]
        marking_definition = json.dumps(marking_definition)
        self.assertFalseWithOptions(marking_definition)

    def test_object_marking_ref_invalid_type(self):
        marking_definition = copy.deepcopy(self.valid_marking_definition)
        marking_definition['object_marking_refs'] = ["indicator--44098fce-860f-48ae-8e50-ebd3cc5e41da"]
        marking_definition = json.dumps(marking_definition)
        self.assertFalseWithOptions(marking_definition)

    def test_granular_marking_circular_ref(self):
        marking_definition = copy.deepcopy(self.valid_marking_definition)
        marking_definition['granular_markings'] = [{
            "marking_ref": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
            "selectors": ["created"]
        }]
        marking_definition = json.dumps(marking_definition)
        self.assertFalseWithOptions(marking_definition)

    def test_granular_marking_invalid_selector(self):
        marking_definition = copy.deepcopy(self.valid_marking_definition)
        marking_definition['granular_markings'] = [{
            "marking_ref": "marking-definition--4478bf48-9af2-4afa-9fc5-7075f6af04af",
            "selectors": ["[0]"]
        }]
        self.assertFalseWithOptions(json.dumps(marking_definition))

    def test_granular_marking_invalid_marking_ref_type(self):
        marking_definition = copy.deepcopy(self.valid_marking_definition)
        marking_definition['granular_markings'] = [{
            "marking_ref": "indicator--3478bf48-9af2-4afa-9fc5-7075f6af04af",
            "selectors": ["created"]
        }]
        self.assertFalseWithOptions(json.dumps(marking_definition))

    def test_marking_definition_invalid_definition(self):
        marking_definition = copy.deepcopy(self.valid_marking_definition)
        marking_definition['definition']['tlp'] = 21
        self.assertFalseWithOptions(json.dumps(marking_definition))


if __name__ == "__main__":
    unittest.main()
