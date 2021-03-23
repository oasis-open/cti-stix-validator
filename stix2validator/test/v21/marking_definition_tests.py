import copy
import json

from . import ValidatorTest
from ... import validate_string

VALID_MARKING_DEFINITION = u"""
{
  "type": "marking-definition",
  "spec_version": "2.1",
  "id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
  "created": "2017-01-20T00:00:00.000Z",
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
        self.assertFalseWithOptions(marking_definition)
        self.assertFalseWithOptions(marking_definition, disabled='custom-content')

        self.check_ignore(marking_definition, 'marking-definition-type,custom-content')

    def test_lax_option(self):
        marking_definition = copy.deepcopy(self.valid_marking_definition)
        marking_definition['definition_type'] = "something"
        self.assertFalseWithOptions(marking_definition)
        self.assertTrueWithOptions(marking_definition, strict=False)

    def test_object_marking_ref_circular_ref(self):
        marking_definition = copy.deepcopy(self.valid_marking_definition)
        marking_definition['object_marking_refs'] = ["marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"]
        self.assertFalseWithOptions(marking_definition)

    def test_object_marking_ref_invalid_type(self):
        marking_definition = copy.deepcopy(self.valid_marking_definition)
        marking_definition['object_marking_refs'] = ["indicator--44098fce-860f-48ae-8e50-ebd3cc5e41da"]
        self.assertFalseWithOptions(marking_definition)

    def test_granular_marking_circular_ref(self):
        marking_definition = copy.deepcopy(self.valid_marking_definition)
        marking_definition['granular_markings'] = [{
            "marking_ref": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
            "selectors": ["created"]
        }]
        self.assertFalseWithOptions(marking_definition)

    def test_granular_marking_invalid_selector(self):
        marking_definition = copy.deepcopy(self.valid_marking_definition)
        marking_definition['granular_markings'] = [{
            "marking_ref": "marking-definition--4478bf48-9af2-4afa-9fc5-7075f6af04af",
            "selectors": ["[0]"]
        }]
        self.assertFalseWithOptions(marking_definition)

    def test_granular_marking_invalid_marking_ref_type(self):
        marking_definition = copy.deepcopy(self.valid_marking_definition)
        marking_definition['granular_markings'] = [{
            "marking_ref": "indicator--3478bf48-9af2-4afa-9fc5-7075f6af04af",
            "selectors": ["created"]
        }]
        self.assertFalseWithOptions(marking_definition)

    def test_marking_definition_invalid_definition(self):
        marking_definition = copy.deepcopy(self.valid_marking_definition)
        marking_definition['definition']['tlp'] = 21
        self.assertFalseWithOptions(marking_definition)

    def test_granular_marking_id_selector(self):
        marking_definition = copy.deepcopy(self.valid_marking_definition)
        marking_definition['granular_markings'] = [{
            "marking_ref": "marking-definition--4478bf48-9af2-4afa-9fc5-7075f6af04af",
            "selectors": ["id"]
        }]
        self.assertTrueWithOptions(marking_definition)

    def test_marking_definition_missing_properties(self):
        marking_definition = {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": "marking-definition--336abc15-1c2a-423c-a7dd-5a821abd96c2",
            "created": "2017-01-20T00:00:00.000Z",
        }
        self.assertFalseWithOptions(marking_definition)

    def test_marking_definition_with_extension(self):
        marking_definition = copy.deepcopy(self.valid_marking_definition)
        del marking_definition['definition']
        del marking_definition['definition_type']
        marking_definition['extensions'] = {
            "extension-definition--9ef47f81-1443-4632-8497-8b2878f8ac21": {
                "extension_type": "property-extension",
                "additional_marking_prop": "if this data is leaked then the world will end",
                "required_data_storage_hash": "sha1024"
            }
        }
        self.assertTrueWithOptions(marking_definition)
