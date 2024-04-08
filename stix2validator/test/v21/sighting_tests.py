import copy
import json

from . import ValidatorTest
from ... import validate_string

VALID_SIGHTING = u"""
{
  "type": "sighting",
  "spec_version": "2.1",
  "id": "sighting--6b0e3956-95f3-4c04-a882-116832996da0",
  "created": "2016-08-22T14:09:00.123Z",
  "modified": "2016-08-22T14:09:00.123Z",
  "first_seen": "2016-08-22T14:09:00.123456Z",
  "sighting_of_ref": "malware--36ffb872-1dd9-446e-b6f5-d58527e5b5d2",
  "observed_data_refs": ["observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf"],
  "where_sighted_refs": ["identity--f431f809-377b-45e0-aa1c-6a4751cae5ff"]
}
"""


class IdentityTestCases(ValidatorTest):
    valid_sighting = json.loads(VALID_SIGHTING)

    def test_wellformed_report(self):
        results = validate_string(VALID_SIGHTING, self.options)
        self.assertTrue(results.is_valid)

    def test_sighting_of_ref(self):
        sighting = copy.deepcopy(self.valid_sighting)
        sighting['sighting_of_ref'] = "bundle--36ffb872-1dd9-446e-b6f5-d58527e5b5d2"
        self.assertFalseWithOptions(sighting)

    def test_observed_data_refs(self):
        sighting = copy.deepcopy(self.valid_sighting)
        sighting['observed_data_refs'].append("tool--36ffb872-1dd9-446e-b6f5-d58527e5b5d2")
        self.assertFalseWithOptions(sighting)

    def test_where_sighted_refs(self):
        sighting = copy.deepcopy(self.valid_sighting)
        sighting['where_sighted_refs'].append("tool--36ffb872-1dd9-446e-b6f5-d58527e5b5d2")
        self.assertFalseWithOptions(sighting)

    def test_invalid_timestamp(self):
        sighting = copy.deepcopy(self.valid_sighting)
        sighting['created'] = "2016-08-32T14:09:00.123Z"
        self.assertFalseWithOptions(sighting)

        sighting['created'] = "2016-08-22T14:09:00.123456Z"
        self.assertFalseWithOptions(sighting)

        sighting['modified'] = "2016-08-22T14:09:00.124Z"
        self.assertTrueWithOptions(sighting)

        sighting['first_seen'] = "2016-08-32T14:09:00.000Z"
        sighting['last_seen'] = "2016-08-22T14:09:00.123Z"
        self.assertFalseWithOptions(sighting)

        sighting['first_seen'] = "2016-08-22T14:09:00.123456Z"
        self.assertFalseWithOptions(sighting)

        sighting['last_seen'] = "2016-08-22T14:09:00.124Z"
        self.assertTrueWithOptions(sighting)
