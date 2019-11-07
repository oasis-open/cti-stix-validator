import copy
import json

from . import ValidatorTest
from ... import validate_parsed_json, validate_string

VALID_COURSE_OF_ACTION = u"""
{
    "type": "course-of-action",
    "spec_version": "2.1",
    "id": "course-of-action--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "created": "2016-04-06T20:03:48.000Z",
    "modified": "2016-04-06T20:03:48.000Z",
    "name": "mitigation-poison-ivy-firewall",
    "description": "Recommended steps to respond to the Poison Ivy malware",
    "action_type": "textual:text/plain",
    "action_reference":
    { "source_name": "internet",
    "url": "hxxps://www.stopthebad.com/poisonivyresponse.asa"
    }
}
"""


class MalwareTestCases(ValidatorTest):
    valid_course_of_action = json.loads(VALID_COURSE_OF_ACTION)

    def test_wellformed_coa(self):
        results = validate_string(VALID_COURSE_OF_ACTION, self.options)
        self.assertTrue(results.is_valid)

    def test_invalid_action_type(self):
        coa = copy.deepcopy(self.valid_course_of_action)
        coa['action_type'] = "invalid"
        results = validate_parsed_json(coa, self.options)
        self.assertEqual(results.is_valid, False)

        self.check_ignore(coa, 'course-of-action-type')

    def test_missing_action(self):
        coa = copy.deepcopy(self.valid_course_of_action)
        del coa['action_reference']
        results = validate_parsed_json(coa, self.options)
        self.assertTrue(results.is_valid)

    def test_invalid_action_bin_and_reference(self):
        coa = copy.deepcopy(self.valid_course_of_action)
        coa['action_bin'] = "SGVsbG8gV29ybGQ="
        results = validate_parsed_json(coa, self.options)
        self.assertEqual(results.is_valid, False)
