import json

from . import ValidatorTest
from ... import validate_string

VALID_COURSE_OF_ACTION = u"""
{
    "type": "course-of-action",
    "spec_version": "2.1",
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
