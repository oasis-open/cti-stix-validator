import copy
import json

from . import ValidatorTest
from ... import validate_string

VALID_CAMPAIGN = u"""
{
    "type": "campaign",
    "spec_version": "2.1",
    "id": "campaign--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
    "created": "2023-03-17T13:37:42.596Z",
    "modified": "2023-09-27T20:12:54.984Z",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "name": "Operation Dream Job",
    "description": "Operation Dream Job was a cyber espionage operation likely conducted by Lazarus Group.",
    "aliases": [
        "Operation Dream Job",
        "Operation North Star",
        "Operation Interception"
    ],
    "first_seen": "2019-09-01T04:00:00.000Z",
    "last_seen": "2020-08-01T04:00:00.000Z"
}
"""


class CampaignTestCases(ValidatorTest):
    valid_campaign = json.loads(VALID_CAMPAIGN)

    def test_wellformed_campaign(self):
        results = validate_string(VALID_CAMPAIGN, self.options)
        self.assertTrue(results.is_valid)

    def test_invalid_timestamp(self):
        campaign = copy.deepcopy(self.valid_campaign)
        campaign['created'] = "2016-09-31T08:17:27.000Z"
        self.assertFalseWithOptions(campaign)

        campaign['created'] = "2023-09-27T20:12:54.984123Z"
        self.assertFalseWithOptions(campaign)

        campaign['modified'] = "2023-09-27T20:12:54.985Z"
        self.assertTrueWithOptions(campaign)

        campaign['first_seen'] = "2019-09-31T04:00:00.000Z"
        self.assertFalseWithOptions(campaign)

        campaign['first_seen'] = "2020-08-01T04:00:00.000123Z"
        self.assertFalseWithOptions(campaign)

        campaign['last_seen'] = "2020-08-01T04:00:00.001Z"
        self.assertTrueWithOptions(campaign)
