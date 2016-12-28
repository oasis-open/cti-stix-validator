import unittest
import copy
import json
from . import ValidatorTest
from .. import validate_string
from ..errors import JSONError

VALID_IDENTITY = """
{
  "type": "identity",
  "id": "identity--2d1c6ab3-5e4e-48ac-a32b-f0c01c2836a8",
  "created": "2014-08-08T15:50:10.983464Z",
  "modified": "2014-08-08T15:50:10.983464Z",
  "name": "ACME Widget, Inc.",
  "identity_class": "organization"
}
"""


class IdentityTestCases(ValidatorTest):
    valid_identity = json.loads(VALID_IDENTITY)

    def test_invalid_check(self):
        # results = validate_string(VALID_IDENTITY, self.options)
        # self.assertTrue(results.is_valid)
        # self.assertFalseWithOptions(VALID_IDENTITY, enabled='abc')
        self.assertRaises(JSONError, self.assertFalseWithOptions, VALID_IDENTITY, enabled='abc')

    def test_wellformed_identity(self):
        results = validate_string(VALID_IDENTITY, self.options)
        self.assertTrue(results.is_valid)

    def test_vocab_identity_class(self):
        identity = copy.deepcopy(self.valid_identity)
        identity['identity_class'] = "corporation"
        identity = json.dumps(identity)
        results = validate_string(identity, self.options)
        self.assertEqual(results.is_valid, False)

    def test_vocab_industry_sector(self):
        identity = copy.deepcopy(self.valid_identity)
        identity['sectors'] = ["something"]
        identity = json.dumps(identity)
        results = validate_string(identity, self.options)
        self.assertEqual(results.is_valid, False)

        self.check_ignore(identity, 'industry-sector')


if __name__ == "__main__":
    unittest.main()
