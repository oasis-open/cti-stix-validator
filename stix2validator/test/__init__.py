import os
import unittest

from .. import ValidationOptions, validate_parsed_json


class ValidatorTest(unittest.TestCase):
    options = ValidationOptions(strict=True)
    custom_schemas = os.path.abspath(os.path.dirname(__file__) + "/test_schemas")

    def check_ignore(self, instance, code):
        """Test that the given instance is valid if the given check is ignored.

        Args:
            instance: The JSON string to be validated.
            error: The numerical code of the check to be ignored.
        """
        self.assertTrueWithOptions(instance, disabled=code)

    def assertTrueWithOptions(self, instance, **kwargs):
        """Test that the given instance is valid when using the validation
        options provided by kwargs.

        Args:
            instance: The JSON string to be validated.
            kwargs: Any number of keyword arguments to be passed to the
                    ValidationOptions constructor.
        """
        if 'strict' in kwargs:
            options = ValidationOptions(**kwargs)
        else:
            options = ValidationOptions(strict=True, **kwargs)
        results = validate_parsed_json(instance, options)
        self.assertTrue(results.is_valid)

    def assertFalseWithOptions(self, instance, **kwargs):
        """Test that the given instance is NOT valid when using the validation
        options provided by kwargs.

        Args:
            instance: The JSON string to be validated.
            kwargs: Any number of keyword arguments to be passed to the
                    ValidationOptions constructor.
        """
        if 'strict' in kwargs:
            options = ValidationOptions(**kwargs)
        else:
            options = ValidationOptions(strict=True, **kwargs)
        results = validate_parsed_json(instance, options)
        self.assertEqual(results.is_valid, False)
