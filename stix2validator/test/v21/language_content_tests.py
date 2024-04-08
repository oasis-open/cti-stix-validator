# coding: utf-8

import copy
import json

from . import ValidatorTest
from ... import validate_string

VALID_LANGUAGE_CONTENT = u"""
{
  "type": "language-content",
  "id": "language-content--fa8daccd-4df2-4e83-93a4-e1990a2355c2",
  "spec_version": "2.1",
  "created": "2018-02-08T21:31:22.007Z",
  "modified": "2018-02-08T21:31:22.007Z",
  "object_ref": "identity--2d1c6ab3-5e4e-48ac-a32b-f0c01c2836a8",
  "object_modified": "2014-08-08T15:50:10.983Z",
  "contents": {
    "es": {
      "identity_class": "organización"
    }
  }
}
"""


class LanguageContentTestCases(ValidatorTest):
    valid_language_content = json.loads(VALID_LANGUAGE_CONTENT)

    def test_wellformed_language_content(self):
        self.assertTrueWithOptions(self.valid_language_content)
        results = validate_string(VALID_LANGUAGE_CONTENT, self.options)
        self.assertTrue(results.is_valid)

    def test_invalid_contents_key(self):
        lang_content = copy.deepcopy(self.valid_language_content)
        lang_content['contents']['español'] = {
            "identity_class": u"organización"
        }
        self.assertFalseWithOptions(lang_content)

    def test_invalid_contents_subkey(self):
        lang_content = copy.deepcopy(self.valid_language_content)
        lang_content['contents']['es'] = {
            "a": "boo"
        }
        self.assertFalseWithOptions(lang_content)

    def test_invalid_timestamp(self):
        lang_content = copy.deepcopy(self.valid_language_content)
        lang_content['created'] = "2018-02-30T21:31:22.007Z"
        self.assertFalseWithOptions(lang_content)

        lang_content['created'] = "2018-02-08T21:31:22.007123Z"
        self.assertFalseWithOptions(lang_content)

        lang_content['modified'] = "2018-02-08T21:31:22.008Z"
        self.assertTrueWithOptions(lang_content)
