import unittest
import copy
import json
from . import ValidatorTest
from .. import validate_string, ValidationError

VALID_CUSTOM_OBJECT = """
{
  "type": "x-example-com-customobject",
  "id": "x-example-com-customobject--4527e5de-8572-446a-a57a-706f15467461",
  "created": "2016-08-01T00:00:00Z",
  "modified": "2016-08-01T00:00:00Z",
  "some_custom_stuff": 14,
  "other_custom_stuff": "hello"
}
"""


class CustomObjectTestCases(ValidatorTest):
    valid_custom_object = json.loads(VALID_CUSTOM_OBJECT)

    def test_wellformed_custom_object(self):
        results = validate_string(VALID_CUSTOM_OBJECT, self.options)
        self.assertTrue(results.is_valid)

    def test_no_type(self):
        custom_obj = copy.deepcopy(self.valid_custom_object)
        del custom_obj['type']
        custom_obj = json.dumps(custom_obj)
        self.assertRaises(ValidationError, validate_string, custom_obj, self.options)

    def test_no_id(self):
        custom_obj = copy.deepcopy(self.valid_custom_object)
        del custom_obj['id']
        custom_obj = json.dumps(custom_obj)
        results = validate_string(custom_obj, self.options)
        self.assertEqual(results.is_valid, False)

    def test_no_created(self):
        custom_obj = copy.deepcopy(self.valid_custom_object)
        del custom_obj['created']
        custom_obj = json.dumps(custom_obj)
        results = validate_string(custom_obj, self.options)
        self.assertEqual(results.is_valid, False)

    def test_no_modified(self):
        custom_obj = copy.deepcopy(self.valid_custom_object)
        del custom_obj['modified']
        custom_obj = json.dumps(custom_obj)
        results = validate_string(custom_obj, self.options)
        self.assertEqual(results.is_valid, False)

    def test_invalid_type_name(self):
        custom_obj = copy.deepcopy(self.valid_custom_object)
        custom_obj['type'] = "corpo_ration"
        custom_obj['id'] = "corpo_ration--4527e5de-8572-446a-a57a-706f15467461"
        custom_obj_string = json.dumps(custom_obj)
        results = validate_string(custom_obj_string, self.options)
        self.assertEqual(results.is_valid, False)

        custom_obj['type'] = "corpor@tion"
        custom_obj['id'] = "corpor@tion--4527e5de-8572-446a-a57a-706f15467461"
        custom_obj_string = json.dumps(custom_obj)
        results = validate_string(custom_obj_string, self.options)
        self.assertEqual(results.is_valid, False)

        self.assertFalseWithOptions(custom_obj_string, enabled='custom-object-prefix-lax')
        self.assertFalseWithOptions(custom_obj_string, disabled='custom-object-prefix-lax')

    def test_invalid_type_name_lax(self):
        custom_obj = copy.deepcopy(self.valid_custom_object)
        custom_obj['type'] = "x-corporation"
        custom_obj['id'] = "x-corporation--4527e5de-8572-446a-a57a-706f15467461"
        custom_obj_string = json.dumps(custom_obj)
        results = validate_string(custom_obj_string, self.options)
        self.assertEqual(results.is_valid, False)

        self.assertTrueWithOptions(custom_obj_string, enabled='custom-object-prefix-lax')
        self.check_ignore(custom_obj_string, 'custom-object-prefix')

    def test_valid_type_name(self):
        custom_obj = copy.deepcopy(self.valid_custom_object)
        custom_obj['type'] = "x-corp-oration"
        custom_obj['id'] = "x-corp-oration--4527e5de-8572-446a-a57a-706f15467461"
        custom_obj_string = json.dumps(custom_obj)
        results = validate_string(custom_obj_string, self.options)
        self.assertTrue(results.is_valid)

    def test_strict_types(self):
        self.assertFalseWithOptions(VALID_CUSTOM_OBJECT, strict_types=True)


if __name__ == "__main__":
    unittest.main()
