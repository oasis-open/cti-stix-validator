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
        # Test spec_version not specified anywhere
        # Fail: defaults to a version that requires spec_version on SDO
        bundle = copy.deepcopy(self.valid_data)
        results = validate_parsed_json(bundle, self.internal_options)
        self.assertFalse(results.is_valid)

    def test_cmd(self):
        # Test spec_version specified only in cmdline option
        # Fail in 2.0: spec_version is required on Bundle
        # Fail in 2.1: spec_version is required on SDO
        for version in VERSION_NUMBERS:
            bundle = copy.deepcopy(self.valid_data)
            self.internal_options.version = version
            results = validate_parsed_json(
                bundle,
                self.internal_options)
            self.assertFalse(results.is_valid)

    def test_bundle(self):
        # Test spec_version specified only on bundle
        for version in VERSION_NUMBERS:
            bundle = copy.deepcopy(self.valid_data)
            bundle['spec_version'] = version
            results = validate_parsed_json(bundle)
            if version == "2.0":
                self.assertTrue(results.is_valid)
            elif version == "2.1":
                # Warn: spec_version is custom on bundle,
                # Error: spec_version is required on SDO
                self.assertFalse(results.is_valid)
                self.assertTrue(len(results.errors) > 0)
                self.assertTrue(len(results.warnings) == 1)

    def test_object(self):
        # Test spec_version specified only on SDO
        bundle = copy.deepcopy(self.valid_data)
        for version in VERSION_NUMBERS:
            bundle['objects'][0]['spec_version'] = version
            results = validate_parsed_json(bundle)
            self.assertTrue(results.is_valid)

    def test_bundle_and_object(self):
        # Test spec_version specified both on bundle and SDO
        bundle = copy.deepcopy(self.valid_data)
        for bundle_version in VERSION_NUMBERS:
            for object_version in VERSION_NUMBERS:
                bundle['spec_version'] = bundle_version
                bundle['objects'][0]['spec_version'] = object_version
                results = validate_parsed_json(bundle)
                self.assertTrue(results.is_valid)
                if bundle_version == "2.0" and object_version == "2.0":
                    # spec_version is custom on object in 2.0
                    self.assertTrue(len(results.warnings) == 1)

                if bundle_version == "2.0" and object_version == "2.1":
                    # spec_version is custom on object in 2.0
                    # Warn: spec_version mismatch, treating as 2.0
                    self.assertTrue(len(results.warnings) == 2)

                if bundle_version == "2.1" and object_version == "2.0":
                    # spec_version is custom on bundle in 2.1
                    # Warn: spec_version mismatch, treating as 2.1
                    self.assertTrue(len(results.warnings) == 2)

                if bundle_version == "2.1" and object_version == "2.1":
                    # spec_version is custom on bundle in 2.1
                    self.assertTrue(len(results.warnings) == 1)

    def test_cmd_and_bundle(self):
        # Test spec_version specified in cmdline option and on bundle
        bundle = copy.deepcopy(self.valid_data)
        for bundle_version in VERSION_NUMBERS:
            for cmd_version in VERSION_NUMBERS:
                bundle['spec_version'] = bundle_version
                self.internal_options.version = cmd_version
                results = validate_parsed_json(
                    bundle,
                    self.internal_options)

                if cmd_version == "2.0" and bundle_version == "2.0":
                    self.assertTrue(results.is_valid)

                elif cmd_version == "2.0" and bundle_version == "2.1":
                    # Fail: treated as 2.0 so bundle version must be 2.0
                    self.assertFalse(results.is_valid)
                    self.assertTrue(len(results.warnings) == 1)

                elif cmd_version == "2.1" and bundle_version == "2.0":
                    self.assertFalse(results.is_valid)
                    self.assertTrue(len(results.errors) == 2)
                    self.assertTrue(len(results.warnings) == 2)

                elif cmd_version == "2.1" and bundle_version == "2.1":
                    self.assertFalse(results.is_valid)
                    self.assertTrue(len(results.warnings) == 1)
                    self.assertTrue(len(results.errors) == 2)

    def test_cmd_and_obj(self):
        # Test spec_version specified in cmdline option and on SDO
        bundle = copy.deepcopy(self.valid_data)
        for cmd_version in VERSION_NUMBERS:
            for obj_version in VERSION_NUMBERS:
                bundle['objects'][0]['spec_version'] = obj_version
                self.internal_options.version = cmd_version
                results = validate_parsed_json(
                    bundle,
                    self.internal_options)

                if cmd_version == "2.0" and obj_version == "2.0":
                    # Fail: spec_version required on bundle for 2.0
                    self.assertFalse(results.is_valid)
                    self.assertTrue(len(results.warnings) == 1)
                    self.assertTrue(len(results.errors) == 1)

                elif cmd_version == "2.0" and obj_version == "2.1":
                    # Fail: spec_version required on bundle for 2.0
                    self.assertFalse(results.is_valid)
                    self.assertTrue(len(results.warnings) == 2)
                    self.assertTrue(len(results.errors) == 1)

                elif cmd_version == "2.1" and obj_version == "2.0":
                    self.assertTrue(len(results.warnings) == 1)
                    self.assertTrue(results.is_valid)

                elif cmd_version == "2.1" and obj_version == "2.1":
                    self.assertTrue(results.is_valid)
                    self.assertTrue(len(results.warnings) == 0)

    def test_all(self):
        # Test spec_version specified in cmdline option, on bundle, and on SDO
        bundle = copy.deepcopy(self.valid_data)
        for cmd_version in VERSION_NUMBERS:
            for bundle_version in VERSION_NUMBERS:
                for obj_version in VERSION_NUMBERS:
                    bundle['spec_version'] = bundle_version
                    bundle['objects'][-1]['spec_version'] = obj_version
                    self.internal_options.version = cmd_version
                    results = validate_parsed_json(
                        bundle,
                        self.internal_options)

                    if cmd_version == "2.0" and bundle_version == "2.0" and obj_version == "2.0":
                        self.assertTrue(results.is_valid)
                        self.assertTrue(len(results.warnings) == 1)

                    if cmd_version == "2.0" and bundle_version == "2.0" and obj_version == "2.1":
                        self.assertTrue(results.is_valid)
                        self.assertTrue(len(results.warnings) == 2)

                    if cmd_version == "2.0" and bundle_version == "2.1" and obj_version == "2.0":
                        # Fail: treated as 2.0 so bundle version must be 2.0
                        self.assertFalse(results.is_valid)
                        self.assertTrue(len(results.warnings) == 2)

                    if cmd_version == "2.0" and bundle_version == "2.1" and obj_version == "2.1":
                        # Fail: treated as 2.0 so bundle version must be 2.0
                        self.assertFalse(results.is_valid)
                        self.assertTrue(len(results.warnings) == 3)

                    if cmd_version == "2.1" and bundle_version == "2.0" and obj_version == "2.0":
                        self.assertTrue(results.is_valid)
                        self.assertTrue(len(results.warnings) == 3)

                    if cmd_version == "2.1" and bundle_version == "2.0" and obj_version == "2.1":
                        self.assertTrue(results.is_valid)
                        self.assertTrue(len(results.warnings) == 2)

                    if cmd_version == "2.1" and bundle_version == "2.1" and obj_version == "2.0":
                        self.assertTrue(results.is_valid)
                        self.assertTrue(len(results.warnings) == 2)

                    if cmd_version == "2.1" and bundle_version == "2.1" and obj_version == "2.1":
                        self.assertTrue(results.is_valid)
                        self.assertTrue(len(results.warnings) == 1)
