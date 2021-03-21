import copy
import json

from . import ValidatorTest
from ... import validate_string

VALID_EXTENSION_DEFINITION = u"""
{
    "id": "extension-definition--04b2d3ef-d061-4912-ab77-6bbe807a5bd5",
    "type": "extension-definition",
    "spec_version": "2.1",
    "name": "New SDO 1",
    "description": "This schema creates a new object type called my-favorite-sdo-1",
    "created": "2014-02-20T09:16:08.989000Z",
    "modified": "2014-02-20T09:16:08.989000Z",
    "created_by_ref": "identity--11b76a96-5d2b-45e0-8a5a-f6994f370731",
    "schema": "https://www.example.com/schema-my-favorite-sdo-1/v1/",
    "version": "1.2.1",
    "extension_types": [ "new-sdo" ]
}
"""
VALID_EXTENSION_NEW_SDO = u"""
{
    "type": "my-favorite-sdo",
    "spec_version": "2.1",
    "id": "my-favorite-sdo--a932fcc6-e032-476c-a26f-cb970a5a1ade",
    "created": "2014-02-20T09:16:08.989000Z",
    "modified": "2014-02-20T09:16:08.989000Z",
    "name": "This is the name of my favorite",
    "some_property_name1": "value1",
    "some_property_name2": "value2",
    "extensions": {
        "extension-definition--04b2d3ef-d061-4912-ab77-6bbe807a5bd5" : {
            "extension_type" : "new-sdo"
        }
    }
}
"""


class NewSDOExtensionTestCases(ValidatorTest):
    valid_ext_definition = json.loads(VALID_EXTENSION_DEFINITION)
    valid_new_sdo = json.loads(VALID_EXTENSION_NEW_SDO)

    def test_wellformed_ext_definition(self):
        results = validate_string(VALID_EXTENSION_DEFINITION, self.options)
        self.assertTrue(results.is_valid)

    def test_ext_defn_invalid_extension_type(self):
        extdef = copy.deepcopy(self.valid_ext_definition)
        extdef['extension_types'] = ["something"]
        self.assertFalseWithOptions(extdef)

    def test_ext_defn_extprops_not_top_level(self):
        extdef = copy.deepcopy(self.valid_ext_definition)
        extdef['extension_properties'] = ["something"]
        self.assertFalseWithOptions(extdef)

        extdef['extension_types'] = ['toplevel-property-extension']
        self.assertTrueWithOptions(extdef)

    def test_toplvl_extension_without_properties(self):
        extension = copy.deepcopy(self.valid_ext_definition)
        extension['extension_types'] = ['toplevel-property-extension']
        self.assertFalseWithOptions(extension)
        self.assertTrueWithOptions(extension, disabled='extension-properties')

        extension['extension_properties'] = ['some_custom_stuff', 'other_custom_stuff']
        self.assertTrueWithOptions(extension)

    def test_no_description(self):
        extdef = copy.deepcopy(self.valid_ext_definition)
        del extdef['description']
        self.assertFalseWithOptions(extdef)
        self.assertTrueWithOptions(extdef, disabled='extension-description')

    def test_wellformed_new_sdo(self):
        newsdo = copy.deepcopy(self.valid_new_sdo)
        self.assertTrueWithOptions(newsdo)

    def test_wellformed_new_sdo_invalid_extension_type(self):
        newsdo = copy.deepcopy(self.valid_new_sdo)
        newsdo['extensions']['extension-definition--04b2d3ef-d061-4912-ab77-6bbe807a5bd5']['extension_type'] = ["something"]
        self.assertFalseWithOptions(newsdo)
