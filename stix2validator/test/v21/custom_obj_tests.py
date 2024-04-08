import copy
import json

import pytest

from . import ValidatorTest
from ... import ValidationError, validate_parsed_json, validate_string

VALID_CUSTOM_OBJECT = u"""
{
  "type": "x-example-com-customobject",
  "spec_version": "2.1",
  "id": "x-example-com-customobject--4527e5de-8572-446a-a57a-706f15467461",
  "created": "2021-02-20T09:16:08.989000Z",
  "modified": "2021-02-20T09:16:08.989000Z",
  "some_custom_stuff": 14,
  "other_custom_stuff": "hello",
  "extensions": {
    "extension-definition--1bba6c39-7ac1-40a2-819a-f33f8ea81a25" : {
       "extension_type" : "new-sdo"
    }
  }
}
"""


class CustomObjectTestCases(ValidatorTest):
    valid_custom_object = json.loads(VALID_CUSTOM_OBJECT)

    def test_wellformed_custom_object(self):
        results = validate_string(VALID_CUSTOM_OBJECT, self.options)
        self.assertTrue(results.is_valid)

    def test_invalid_timestamp(self):
        custom_obj = copy.deepcopy(self.valid_custom_object)
        custom_obj['created'] = "2021-02-30T09:16:08.989000Z"
        self.assertFalseWithOptions(custom_obj)

        custom_obj['created'] = "2021-02-20T09:16:08.989123Z"
        self.assertFalseWithOptions(custom_obj)

        custom_obj['modified'] = "2021-02-20T09:16:08.990Z"
        self.assertTrueWithOptions(custom_obj)

    def test_no_type(self):
        custom_obj = copy.deepcopy(self.valid_custom_object)
        del custom_obj['type']
        self.assertRaises(ValidationError, validate_parsed_json, custom_obj, self.options)

    def test_no_id(self):
        custom_obj = copy.deepcopy(self.valid_custom_object)
        del custom_obj['id']
        with pytest.raises(ValidationError):
            validate_parsed_json(custom_obj, self.options)

    def test_no_created(self):
        custom_obj = copy.deepcopy(self.valid_custom_object)
        del custom_obj['created']
        results = validate_parsed_json(custom_obj, self.options)
        self.assertEqual(results.is_valid, False)

    def test_no_modified(self):
        custom_obj = copy.deepcopy(self.valid_custom_object)
        del custom_obj['modified']
        results = validate_parsed_json(custom_obj, self.options)
        self.assertEqual(results.is_valid, False)

    def test_invalid_type_name(self):
        custom_obj = copy.deepcopy(self.valid_custom_object)
        custom_obj['type'] = "corpo_ration"
        custom_obj['id'] = "corpo_ration--4527e5de-8572-446a-a57a-706f15467461"
        self.assertFalseWithOptions(custom_obj)

        custom_obj['type'] = "corpor@tion"
        custom_obj['id'] = "corpor@tion--4527e5de-8572-446a-a57a-706f15467461"
        self.assertFalseWithOptions(custom_obj)

        self.assertFalseWithOptions(custom_obj, enabled='extensions-use')
        self.assertFalseWithOptions(custom_obj, disabled='extensions-use')

        self.assertFalseWithOptions(custom_obj, enabled='custom-prefix-lax')
        self.assertFalseWithOptions(custom_obj, disabled='extensions-use,custom-prefix')

    def test_invalid_type_name_lax(self):
        custom_obj = copy.deepcopy(self.valid_custom_object)
        custom_obj['type'] = "x-corporation"
        custom_obj['id'] = "x-corporation--4527e5de-8572-446a-a57a-706f15467461"

        self.assertTrueWithOptions(custom_obj, enabled='custom-prefix-lax')
        self.assertFalseWithOptions(custom_obj, disabled='extensions-use')
        self.assertTrueWithOptions(custom_obj, disabled='extensions-use,custom-prefix')

    def test_valid_type_name(self):
        custom_obj = copy.deepcopy(self.valid_custom_object)
        custom_obj['type'] = "x-corp-oration"
        custom_obj['id'] = "x-corp-oration--4527e5de-8572-446a-a57a-706f15467461"
        self.assertTrueWithOptions(custom_obj, strict=True, strict_properties=True)

    def test_strict_types(self):
        self.assertFalseWithOptions(self.valid_custom_object, strict_types=True)

    def test_invalid_type_starting_character_in_instance(self):
        new_object = copy.deepcopy(self.valid_custom_object)
        new_object['type'] = 'X-example-com-customobject'
        new_object['id'] = new_object['type'] + '--' + new_object['id'].split('--')[1]

        self.assertFalseWithOptions(new_object)

    def test_invalid_property_name_starting_character_in_instance(self):
        new_object = copy.deepcopy(self.valid_custom_object)
        new_object['9ome_custom_stuff'] = new_object.pop('some_custom_stuff')

        self.assertFalseWithOptions(new_object)
