import copy
import json
import unittest

from . import ValidatorTest
from .. import ValidationError, validate_instance, validate_string


VALID_CUSTOM_OBJECT = """
{
  "type": "x-example-com-customobject",
  "id": "x-example-com-customobject--4527e5de-8572-446a-a57a-706f15467461",
  "created": "2016-08-01T00:00:00.000Z",
  "modified": "2016-08-01T00:00:00.000Z",
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
        self.assertRaises(ValidationError, validate_instance, custom_obj, self.options)

    def test_no_id(self):
        custom_obj = copy.deepcopy(self.valid_custom_object)
        del custom_obj['id']
        results = validate_instance(custom_obj, self.options)
        self.assertEqual(results.is_valid, False)

    def test_no_created(self):
        custom_obj = copy.deepcopy(self.valid_custom_object)
        del custom_obj['created']
        results = validate_instance(custom_obj, self.options)
        self.assertEqual(results.is_valid, False)

    def test_no_modified(self):
        custom_obj = copy.deepcopy(self.valid_custom_object)
        del custom_obj['modified']
        results = validate_instance(custom_obj, self.options)
        self.assertEqual(results.is_valid, False)

    def test_invalid_type_name(self):
        custom_obj = copy.deepcopy(self.valid_custom_object)
        custom_obj['type'] = "corpo_ration"
        custom_obj['id'] = "corpo_ration--4527e5de-8572-446a-a57a-706f15467461"
        results = validate_instance(custom_obj, self.options)
        self.assertEqual(results.is_valid, False)

        custom_obj['type'] = "corpor@tion"
        custom_obj['id'] = "corpor@tion--4527e5de-8572-446a-a57a-706f15467461"
        results = validate_instance(custom_obj, self.options)
        self.assertEqual(results.is_valid, False)

        self.assertFalseWithOptions(custom_obj, enabled='custom-prefix-lax')
        self.assertFalseWithOptions(custom_obj, disabled='custom-prefix-lax')

    def test_invalid_type_name_lax(self):
        custom_obj = copy.deepcopy(self.valid_custom_object)
        custom_obj['type'] = "x-corporation"
        custom_obj['id'] = "x-corporation--4527e5de-8572-446a-a57a-706f15467461"
        results = validate_instance(custom_obj, self.options)
        self.assertEqual(results.is_valid, False)

        self.assertTrueWithOptions(custom_obj, enabled='custom-prefix-lax')
        self.check_ignore(custom_obj, 'custom-prefix')

    def test_valid_type_name(self):
        custom_obj = copy.deepcopy(self.valid_custom_object)
        custom_obj['type'] = "x-corp-oration"
        custom_obj['id'] = "x-corp-oration--4527e5de-8572-446a-a57a-706f15467461"
        results = validate_instance(custom_obj, self.options)
        self.assertTrue(results.is_valid)

    def test_strict_types(self):
        self.assertFalseWithOptions(self.valid_custom_object, strict_types=True)


if __name__ == "__main__":
    unittest.main()
