import copy
import json

from . import ValidatorTest
from ... import validate_string

VALID_LOCATION = u"""
{
  "type": "location",
  "spec_version": "2.1",
  "id": "location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64",
  "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
  "created": "2016-04-06T20:03:00.000Z",
  "modified": "2016-04-06T20:03:00.000Z",
  "region": "south-eastern-asia",
  "country": "th",
  "administrative_area": "Tak",
  "postal_code": "63170"
}
"""


class LocationTestCases(ValidatorTest):
    valid_location = json.loads(VALID_LOCATION)

    def test_wellformed_location(self):
        results = validate_string(VALID_LOCATION, self.options)
        self.assertTrue(results.is_valid)

    def test_invalid_timestamp(self):
        location = copy.deepcopy(self.valid_location)
        location['created'] = "2016-04-31T20:03:00.000Z"
        self.assertFalseWithOptions(location)

        location['created'] = "2016-04-06T20:03:00.000123Z"
        self.assertFalseWithOptions(location)

        location['modified'] = "2016-04-06T20:03:00.001Z"
        self.assertTrueWithOptions(location)

    def test_location_lat_long(self):
        location = copy.deepcopy(self.valid_location)
        location['latitude'] = 48.8566
        location['longitude'] = 2.3522
        self.assertTrueWithOptions(location)

        self.check_ignore(location, 'region')

    def test_vocab_region(self):
        location = copy.deepcopy(self.valid_location)
        location['region'] = 'global'
        self.assertFalseWithOptions(location, strict=True)

        self.check_ignore(location, 'region')

    def test_vocab_country(self):
        location = copy.deepcopy(self.valid_location)
        location['country'] = 'xx'
        self.assertFalseWithOptions(location, strict=True)

        self.check_ignore(location, 'countries')
