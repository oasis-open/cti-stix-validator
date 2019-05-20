import copy
import json

from . import ValidatorTest
from ... import ValidationOptions, validate_parsed_json

VALID_BUNDLE = u"""
{
  "type": "bundle",
  "id": "bundle--44af6c39-c09b-49c5-9de2-394224b04982",
  "objects": [
    {
      "type": "identity",
      "id": "identity--8ae20dde-83d4-4218-88fd-41ef0dabf9d1",
      "created": "2016-08-22T14:09:00.123Z",
      "modified": "2016-08-22T14:09:00.123Z",
      "name": "mitre.org",
      "identity_class": "organization"
    }
  ]
}
"""

VERSION_NUMBERS = ["2.0", "2.1"]


class SpecVersionTestCases(ValidatorTest):
    valid_data = json.loads(VALID_BUNDLE)
    internal_options = ValidationOptions()

    def test_empty(self):
        observed_data = copy.deepcopy(self.valid_data)
        results = validate_parsed_json(observed_data, self.internal_options)
        self.assertFalse(results.is_valid)

    def test_cmd(self):
        for version in VERSION_NUMBERS:
            observed_data = copy.deepcopy(self.valid_data)
            self.internal_options.version = version
            results = validate_parsed_json(
                observed_data,
                self.internal_options)
            if version == "2.0":
                self.assertTrue(results.is_valid)
            elif version == "2.1":
                self.assertFalse(results.is_valid)

    def test_bundle(self):
        for version in VERSION_NUMBERS:
            observed_data = copy.deepcopy(self.valid_data)
            observed_data['spec_version'] = version
            results = validate_parsed_json(observed_data)
            if version == "2.0":
                self.assertTrue(results.is_valid)
            elif version == "2.1":
                self.assertFalse(results.is_valid)
                self.assertTrue(len(results.errors) == 1)
                self.assertTrue(len(results.warnings) == 1)

    def test_object(self):
        observed_data = copy.deepcopy(self.valid_data)
        for version in VERSION_NUMBERS:
            observed_data['objects'][0]['spec_version'] = version
            results = validate_parsed_json(observed_data)
            self.assertTrue(results.is_valid)

    def test_bundle_and_object(self):
        observed_data = copy.deepcopy(self.valid_data)
        for bundle_version in VERSION_NUMBERS:
            for object_version in VERSION_NUMBERS:
                observed_data['spec_version'] = bundle_version
                observed_data['objects'][0]['spec_version'] = object_version
                results = validate_parsed_json(observed_data)
                self.assertTrue(results.is_valid)

    def test_cmd_and_bundle(self):
        observed_data = copy.deepcopy(self.valid_data)
        for bundle_version in VERSION_NUMBERS:
            for cmd_version in VERSION_NUMBERS:
                observed_data['spec_version'] = bundle_version
                self.internal_options.version = cmd_version
                results = validate_parsed_json(
                    observed_data,
                    self.internal_options)

                if cmd_version == "2.0" and bundle_version == "2.0":
                    self.assertTrue(results.is_valid)

                elif cmd_version == "2.0" and bundle_version == "2.1":
                    self.assertTrue(results.is_valid)

                elif cmd_version == "2.1" and bundle_version == "2.0":
                    self.assertFalse(results.is_valid)
                    self.assertTrue(len(results.errors) == 1)
                    self.assertTrue(len(results.warnings) == 2)

                elif cmd_version == "2.1" and bundle_version == "2.1":
                    self.assertFalse(results.is_valid)
                    self.assertTrue(len(results.warnings) == 1)
                    self.assertTrue(len(results.errors) == 1)

    def test_cmd_and_obj(self):
        observed_data = copy.deepcopy(self.valid_data)
        for cmd_version in VERSION_NUMBERS:
            for obj_version in VERSION_NUMBERS:
                observed_data['objects'][0]['spec_version'] = obj_version
                self.internal_options.version = cmd_version
                results = validate_parsed_json(
                    observed_data,
                    self.internal_options)
                if cmd_version == "2.0" and obj_version == "2.0":
                    self.assertTrue(results.is_valid)
                    self.assertTrue(len(results.warnings) == 1)

                elif cmd_version == "2.0" and obj_version == "2.1":
                    self.assertTrue(results.is_valid)
                    self.assertTrue(len(results.warnings) == 2)

                elif cmd_version == "2.1" and obj_version == "2.0":
                    self.assertTrue(len(results.warnings) == 1)
                    self.assertTrue(results.is_valid)

                elif cmd_version == "2.1" and obj_version == "2.1":
                    self.assertTrue(results.is_valid)
                    self.assertTrue(len(results.warnings) == 0)

    def test_all(self):
        observed_data = copy.deepcopy(self.valid_data)
        for cmd_version in VERSION_NUMBERS:
            for bundle_version in VERSION_NUMBERS:
                for obj_version in VERSION_NUMBERS:
                    observed_data['spec_version'] = bundle_version
                    observed_data['objects'][-1]['spec_version'] = obj_version
                    self.internal_options.version = cmd_version
                    results = validate_parsed_json(
                        observed_data,
                        self.internal_options)

                    if cmd_version == "2.0" and bundle_version == "2.0" and obj_version == "2.0":
                        self.assertTrue(results.is_valid)
                        self.assertTrue(len(results.warnings) == 1)

                    if cmd_version == "2.1" and bundle_version == "2.0" and obj_version == "2.0":
                        self.assertTrue(results.is_valid)
                        self.assertTrue(len(results.warnings) == 3)

                    if cmd_version == "2.0" and bundle_version == "2.1" and obj_version == "2.0":
                        self.assertTrue(results.is_valid)
                        self.assertTrue(len(results.warnings) == 2)

                    if cmd_version == "2.0" and bundle_version == "2.0" and obj_version == "2.1":
                        self.assertTrue(results.is_valid)
                        self.assertTrue(len(results.warnings) == 2)

                    if cmd_version == "2.1" and bundle_version == "2.1" and obj_version == "2.0":
                        self.assertTrue(results.is_valid)
                        self.assertTrue(len(results.warnings) == 2)

                    if cmd_version == "2.0" and bundle_version == "2.1" and obj_version == "2.1":
                        self.assertTrue(results.is_valid)
                        self.assertTrue(len(results.warnings) == 3)

                    if cmd_version == "2.1" and bundle_version == "2.1" and obj_version == "2.1":
                        self.assertTrue(results.is_valid)
                        self.assertTrue(len(results.warnings) == 1)
