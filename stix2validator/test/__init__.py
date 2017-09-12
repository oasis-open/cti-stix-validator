import os
import unittest

from .. import ValidationOptions, print_results, validate_instance

SCHEMA_DIR = os.path.abspath(os.path.dirname(__file__) + "../../schemas")


class ValidatorTest(unittest.TestCase):
    options = ValidationOptions(schema_dir=SCHEMA_DIR, strict=True)

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
            options = ValidationOptions(schema_dir=SCHEMA_DIR, **kwargs)
        else:
            options = ValidationOptions(schema_dir=SCHEMA_DIR, strict=True,
                                        **kwargs)
        results = validate_instance(instance, options)
        print_results(results)
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
            options = ValidationOptions(schema_dir=SCHEMA_DIR, **kwargs)
        else:
            options = ValidationOptions(schema_dir=SCHEMA_DIR, strict=True,
                                        **kwargs)
        results = validate_instance(instance, options)
        self.assertEqual(results.is_valid, False)
