import copy
import json

from . import ValidatorTest
from ... import validate_string

VALID_INCIDENT = u"""
{
  "type": "incident",
  "spec_version": "2.1",
  "id": "incident--dd8651ee-d529-44fe-b063-bb6f006fbe5c",
  "created": "2021-03-20T08:17:27.000Z",
  "modified": "2021-03-20T08:17:27.000Z",
  "name": "FUBAR",
  "description": "Something happened"
}
"""


class IncidentTestCases(ValidatorTest):
    valid_incident = json.loads(VALID_INCIDENT)

    def test_wellformed_incident(self):
        results = validate_string(VALID_INCIDENT, self.options)
        self.assertTrue(results.is_valid)

    def test_invalid_timestamp(self):
        incident = self.valid_incident.copy()
        incident['created'] = "2021-03-32T08:17:27.000Z"
        self.assertFalseWithOptions(incident)

        incident['created'] = "2021-03-20T08:17:27.000123Z"
        self.assertFalseWithOptions(incident)

        incident['modified'] = "2021-03-20T08:17:27.001Z"
        self.assertTrueWithOptions(incident)

    def test_missing_name(self):
        incident = copy.deepcopy(self.valid_incident)
        del incident['name']
        self.assertFalseWithOptions(incident)
