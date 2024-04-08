import copy
import json

from . import ValidatorTest
from ... import validate_string

VALID_COURSE_OF_ACTION = u"""
{
    "type": "course-of-action",
    "id": "course-of-action--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "created": "2016-04-06T20:03:48.000Z",
    "modified": "2016-04-06T20:03:48.000Z",
    "name": "mitigation-poison-ivy-firewall",
    "description": "Recommended steps to respond to the Poison Ivy malware"
}
"""


class CoATestCases(ValidatorTest):
    valid_course_of_action = json.loads(VALID_COURSE_OF_ACTION)

    def test_wellformed_coa(self):
        results = validate_string(VALID_COURSE_OF_ACTION, self.options)
        self.assertTrue(results.is_valid)

    def test_invalid_timestamp(self):
        coa = copy.deepcopy(self.valid_course_of_action)
        coa['created'] = "2016-11-31T01:00:00.000Z"
        self.assertFalseWithOptions(coa)

        coa['created'] = "2016-04-06T20:03:48.123Z"
        self.assertFalseWithOptions(coa)

        coa['modified'] = "2016-04-06T20:03:48.123Z"
        self.assertTrueWithOptions(coa)
