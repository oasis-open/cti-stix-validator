"""Custom jsonschema.IValidator class and validator functions.
"""

import os
import json
import fnmatch
import datetime
from itertools import chain
from collections import Iterable

from jsonschema import Draft4Validator, RefResolver
from jsonschema import exceptions as schema_exceptions
from six import text_type, iteritems
import requests_cache

from . import output, musts, shoulds
from .errors import (SchemaError, SchemaInvalidError, pretty_error,
                     ValidationError, NoJSONFileFoundError)
from .util import ValidationOptions


class CustomDraft4Validator(Draft4Validator):
    """Custom validator class for JSON Schema Draft 4.

    """
    def __init__(self, schema, types=(), resolver=None, format_checker=None,
                 options=ValidationOptions()):
        super(CustomDraft4Validator, self).__init__(schema, types, resolver,
                                                    format_checker)
        self.musts_list = musts.list_musts(options)
        self.shoulds_list = shoulds.list_shoulds(options)

    def iter_errors_more(self, instance, check_musts=True):
        """Perform additional validation not possible merely with JSON schemas.

        Args:
            instance: The STIX object to be validated.
            check_musts: If True, this function will check against the
                additional mandatory "MUST" requirements which cannot be
                enforced by schemas. If False, this function will check against
                recommended "SHOULD" best practices instead. This function will
                never check both; to do so call it twice.
        """
        # Ensure `instance` is a whole STIX object, not just a property of one
        if not (type(instance) is dict and 'id' in instance and 'type' in instance):
            return

        if check_musts:
            validators = self.musts_list
        else:
            validators = self.shoulds_list

        # Perform validation
        for v_function in validators:
            result = v_function(instance)
            if isinstance(result, Iterable):
                for x in result:
                    yield x
            elif result is not None:
                yield result

        # Validate any child STIX objects
        for field in instance:
            if type(instance[field]) is list:
                for obj in instance[field]:
                    for err in self.iter_errors_more(obj, check_musts):
                        yield err

    def get_list(self):
        """Return a combined list of all musts and shoulds this validator will
        perform, both MUSTs and SHOULDs.
        """
        return self.musts_list + self.shoulds_list


class BaseResults(object):
    """Base class for all validation result types.
    """
    def __init__(self, is_valid=False):
        self.is_valid = is_valid

    @property
    def is_valid(self):
        """Returns ``True`` if the validation attempt was successful and
        ``False`` otherwise.
        """
        return self._is_valid

    @is_valid.setter
    def is_valid(self, value):
        self._is_valid = bool(value)

    def as_dict(self):
        """Return a dictionary representation of this class.

        Keys:
            ``'result'``: The validation result. Values will be ``True`` or
            ``False``.

        """
        return {'result': self.is_valid}

    def as_json(self):
        """Returns a JSON representation of this class instance.
        """
        return json.dumps(self.as_dict())


class ValidationResults(BaseResults):
    """Results of JSON schema validation.

    Args:
        is_valid: The validation result.
        errors: A list of exception strings reported by the JSON validation
            engine.
        fatal: A fatal error.
        warnings: A list of warning strings reported by our custom validators.
        fn: The filename/path for the file that was validated; None if a string
            was validated.

    Attributes:
        is_valid: ``True`` if the validation was successful and ``False``
            otherwise.

    """
    def __init__(self, is_valid=False, errors=None, fatal=None, warnings=None,
                 fn=None):
        super(ValidationResults, self).__init__(is_valid)
        self.errors = errors
        self.fatal = fatal
        self.warnings = warnings
        self.fn = fn

    @property
    def errors(self):
        """"A list of :class:`SchemaError` validation errors.
        """
        return self._errors

    @errors.setter
    def errors(self, value):
        if not value:
            self._errors = []
        elif hasattr(value, "__iter__"):
            self._errors = [SchemaError(x) for x in value]
        else:
            self._errors = [SchemaError(value)]

    def as_dict(self):
        """A dictionary representation of the :class:`.ValidationResults`
        instance.

        Keys:
            * ``'result'``: The validation results (``True`` or ``False``)
            * ``'errors'``: A list of validation errors.
        Returns:

            A dictionary representation of an instance of this class.

        """
        d = super(ValidationResults, self).as_dict()

        if self.errors:
            d['errors'] = [x.as_dict() for x in self.errors]

        return d


class ValidationErrorResults(BaseResults):
    """Results of a failed validation due to a raised Exception.

    Args:
        error: An ``Exception`` instance raised by validation code.

    Attributes:
        is_valid: Always ``False``.
        error: The string representation of the Exception being passed in.
        exception: The exception which produced these results.

    """
    def __init__(self, error):
        self._is_valid = False
        self.error = text_type(error)
        self.exception = error

    def as_dict(self):
        d = super(ValidationErrorResults, self).as_dict()
        d['error'] = self.error

        return d


def is_json(fn):
    """Returns ``True`` if the input filename `fn` ends with a JSON extension.
    """
    return os.path.isfile(fn) and fn.lower().endswith('.json')


def list_json_files(directory, recursive=False):
    """Return a list of file paths for JSON files within `directory`.

    Args:
        directory: A path to a directory.
        recursive: If ``True``, this function will descend into all
            subdirectories.

    Returns:
        A list of JSON file paths directly under `directory`.

    """
    json_files = []

    for top, _, files in os.walk(directory):
        # Get paths to each file in `files`
        paths = (os.path.join(top, f) for f in files)

        # Add all the .json files to our return collection
        json_files.extend(x for x in paths if is_json(x))

        if not recursive:
            break

    return json_files


def get_json_files(files, recursive=False):
    """Return a list of files to validate from `files`. If a member of `files`
    is a directory, its children with a ``.json`` extension will be added to
    the return value.

    Args:
        files: A list of file paths and/or directory paths.
        recursive: If ``true``, this will descend into any subdirectories
            of input directories.

    Returns:
        A list of file paths to validate.

    """
    json_files = []

    if not files:
        return json_files

    for fn in files:
        if os.path.isdir(fn):
            children = list_json_files(fn, recursive)
            json_files.extend(children)
        elif is_json(fn):
            json_files.append(fn)
        else:
            continue

    if not json_files:
        raise NoJSONFileFoundError("No JSON files found!")
    return json_files


def run_validation(options):
    """Validate files based on command line options.

    Args:
        options: An instance of ``ValidationOptions`` containing options for
            this validation run.

    """
    # The JSON files to validate
    try:
        files = get_json_files(options.files, options.recursive)
    except NoJSONFileFoundError as e:
        output.error(e.message)

    results = {}
    for fn in files:
        results[fn] = validate_file(fn, options)

    return results


def validate_file(fn, options=None):
    """Validate the input document `fn` according to the options passed in.

    If any exceptions are raised during validation, no further validation
    will take place.

    Args:
        fn: The filename of the JSON file to be validated.
        options: An instance of ``ValidationOptions``.

    Returns:
        An instance of ValidationResults.

    """
    results = ValidationResults(fn=fn)
    output.info("Performing JSON schema validation on %s" % fn)

    if not options:
        options = ValidationOptions(files=fn)

    try:
        with open(fn) as instance_file:
            instance = json.load(instance_file)

        if options.files:
            results = schema_validate(instance, options)

    except SchemaInvalidError as ex:
        results.fatal = ValidationErrorResults(ex)
        msg = ("File '{fn}' was schema-invalid. No further validation "
               "will be performed.")
        output.info(msg.format(fn=fn))
    except Exception as ex:
        import traceback
        print(traceback.format_exc())
        results.fatal = ValidationErrorResults(ex)
        msg = ("Unexpected error occurred with file '{fn}'. No further "
               "validation will be performed: {error}")
        output.info(msg.format(fn=fn, error=str(ex)))

    if results.errors or results.fatal:
        results.is_valid = False

    return results


def validate_string(string, options=None):
    """Validate the input `string` according to the options passed in.

    If any exceptions are raised during validation, no further validation
    will take place.

    Args:
        string: The string containing the JSON to be validated.
        options: An instance of ``ValidationOptions``.

    Returns:
        An instance of ValidationResults.

    """
    results = ValidationResults(fn="input string")
    output.info("Performing JSON schema validation on input string: " + string)
    instance = json.loads(string)

    if not options:
        options = ValidationOptions()

    try:
        results = schema_validate(instance, options)
    except SchemaInvalidError as ex:
        results.fatal = ValidationErrorResults(ex)
        msg = ("String was schema-invalid. No further validation "
               "will be performed.")
        output.info(msg.format(string=string))

    if results.errors or results.fatal:
        results.is_valid = False

    return results


def load_validator(schema_path, schema, options, custom=True):
    """Create a JSON schema validator for the given schema.

    Args:
        schema_path: The filename of the JSON schema.
        schema: A Python object representation of the same schema.
        options: ValidationOptions instance with validation options for this
            validator.
        custom: A boolean, True indicating the CustomDraft4Validator should be
            used, False indicating the default Draft4Validator should be used.

    Returns:
        An instance of Draft4Validator.

    """
    # Get correct prefix based on OS
    if os.name == 'nt':
        file_prefix = 'file:///'
    else:
        file_prefix = 'file:'

    resolver = RefResolver(file_prefix + schema_path.replace("\\", "/"), schema)

    if custom:
        validator = CustomDraft4Validator(schema, resolver=resolver, options=options)
    else:
        validator = Draft4Validator(schema, resolver=resolver)

    return validator


def find_schema(schema_dir, obj_type):
    """Search the `schema_dir` directory for a schema called `obj_type`.json.
    Return the file path of the first match it finds.
    """
    for root, dirnames, filenames in os.walk(schema_dir):
        for filename in fnmatch.filter(filenames, obj_type + '.json'):
            return os.path.join(root, filename)


def load_schema(schema_path):
    """Load the JSON schema at the given path as a Python object.

    Args:
        schema_path: A filename for a JSON schema.

    Returns:
        A Python object representation of the schema.

    """
    try:
        with open(schema_path) as schema_file:
            schema = json.load(schema_file)
    except ValueError as e:
        raise SchemaInvalidError('Invalid JSON in schema or included schema: '
                                 '%s\n%s' % (schema_file.name, str(e)))

    return schema


def object_validate(sdo, options, error_gens):
    """Validate a single STIX object against its type's schema.
    """
    try:
        sdo_schema_path = find_schema(options.schema_dir, sdo['type'])
        sdo_schema = load_schema(sdo_schema_path)
    except (KeyError, TypeError):
        # Assume a custom object with no schema
        try:
            sdo_schema_path = find_schema(options.schema_dir, 'core')
            sdo_schema = load_schema(sdo_schema_path)
        except (KeyError, TypeError):
            raise SchemaInvalidError("Cannot locate a schema for the "
                                     "object's type, nor the base "
                                     "schema (core.json).")

    if sdo['type'] == 'observed-data':
        # Validate against schemas for specific object types later
        sdo_schema['allOf'][1]['properties']['objects'] = {
            "objects": {
                "type": "object",
                "minProperties": 1
            }
        }

    # Don't use custom validator; only check schemas, no additional checks
    sdo_validator = load_validator(sdo_schema_path, sdo_schema,
                                   options, custom=False)
    try:
        sdo_errors = sdo_validator.iter_errors(sdo)
    except schema_exceptions.RefResolutionError:
        raise SchemaInvalidError('Invalid JSON schema: a JSON '
                                 'reference failed to resolve')

    if 'id' in sdo:
        error_prefix = sdo['id'] + ": "
    else:
        error_prefix = ''
    error_gens.append((sdo_errors, error_prefix))

    # Validate each cyber observable object separately
    if sdo['type'] == 'observed-data' and 'objects' in sdo:
        for key, obj in iteritems(sdo['objects']):
            try:
                obj_schema_path = find_schema(options.schema_dir, obj['type'])
                obj_schema = load_schema(obj_schema_path)
            except (KeyError, TypeError):
                # Assume a custom object with no schema
                try:
                    obj_schema_path = find_schema(options.schema_dir,
                                                  'cyber-observable-core')
                    obj_schema = load_schema(obj_schema_path)
                except (KeyError, TypeError):
                    raise SchemaInvalidError("Cannot locate a schema for the "
                                             "object's type, nor the base "
                                             "schema (core.json).")

            obj_validator = load_validator(obj_schema_path, obj_schema,
                                           options, custom=False)
            try:
                obj_errors = obj_validator.iter_errors(obj)
            except schema_exceptions.RefResolutionError:
                raise SchemaInvalidError('Invalid JSON schema: a JSON '
                                         'reference failed to resolve')
            error_gens.append((obj_errors,
                               error_prefix + 'object \'' + key + '\': '))

    return error_gens


def schema_validate(instance, options):
    """Perform STIX JSON Schema validation against the input JSON.
    Find the correct schema by looking at the 'type' property of the
    `instance` JSON object.

    Args:
        instance: A STIX JSON string.
        options: ValidationOptions instance with validation options for this
            validation run.

    Returns:
        A dictionary of validation results

    """
    if 'type' not in instance:
        raise ValidationError("Input must be an object with a 'type' property.")

    # Find and load the schema
    try:
        schema_path = find_schema(options.schema_dir, instance['type'])
        schema = load_schema(schema_path)
    except (KeyError, TypeError):
        # Assume a custom object with no schema
        try:
            schema_path = find_schema(options.schema_dir, 'core')
            schema = load_schema(schema_path)
        except (KeyError, TypeError):
            raise SchemaInvalidError("Cannot locate a schema for the object's "
                                     "type, nor the base schema (core.json).")

    # Validate against schemas for specific object types later
    if instance['type'] == 'bundle':
        schema['properties']['objects'] = {
            "objects": {
                "type": "array",
                "minItems": 1
            }
        }
    elif instance['type'] == 'observed-data':
        schema['allOf'][1]['properties']['objects'] = {
            "objects": {
                "type": "object",
                "minProperties": 1
            }
        }

    # Validate the schema first
    try:
        CustomDraft4Validator.check_schema(schema)
    except schema_exceptions.SchemaError as e:
        raise SchemaInvalidError('Invalid JSON schema: ' + str(e))

    # Cache data from external sources; used in some checks
    if not options.no_cache:
        requests_cache.install_cache(expire_after=datetime.timedelta(weeks=1))
    if options.refresh_cache:
        now = datetime.datetime.utcnow()
        requests_cache.get_cache().remove_old_entries(now)

    validator = load_validator(schema_path, schema, options)
    output.info("Running the following additional checks: %s."
                % ", ".join(x.__name__ for x in validator.get_list()))

    # Actual validation of JSON document
    try:
        some_errors = validator.iter_errors(instance)
        more_errors = validator.iter_errors_more(instance)
        warnings = validator.iter_errors_more(instance, False)

        if options.strict:
            chained_errors = chain(some_errors, more_errors, warnings)
            warnings = []
        else:
            chained_errors = chain(some_errors, more_errors)
            warnings = [pretty_error(x, options.verbose) for x in warnings]
    except schema_exceptions.RefResolutionError:
        raise SchemaInvalidError('Invalid JSON schema: a JSON reference '
                                 'failed to resolve')

    # List of error generators and message prefixes (to denote which object the
    # error comes from)
    error_gens = [(chained_errors, '')]

    # Validate each object in a bundle separately
    if instance['type'] == 'bundle' and 'objects' in instance:
        for sdo in instance['objects']:
            object_validate(sdo, options, error_gens)
    else:
        object_validate(instance, options, error_gens)

    # Clear requests cache if commandline flag was set
    if options.clear_cache:
        now = datetime.datetime.utcnow()
        requests_cache.get_cache().remove_old_entries(now)

    # Prepare the list of errors
    error_list = []
    for gen, prefix in error_gens:
        for error in gen:
            msg = prefix + pretty_error(error, options.verbose)
            error_list.append(SchemaError(msg))

    if error_list:
        valid = False
    else:
        valid = True

    return ValidationResults(is_valid=valid, errors=error_list,
                             warnings=warnings)
