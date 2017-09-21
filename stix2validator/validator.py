"""Custom jsonschema.IValidator class and validator functions.
"""

from collections import Iterable
import io
import datetime
import errno
from itertools import chain
import os
import sys

from appdirs import AppDirs
from jsonschema import Draft4Validator, RefResolver
from jsonschema import exceptions as schema_exceptions
import requests_cache
import simplejson as json
from six import iteritems, text_type

from . import musts, output, shoulds
from .errors import (NoJSONFileFoundError, SchemaError, SchemaInvalidError,
                     ValidationError, pretty_error)
from .util import ValidationOptions


def _is_stix_obj(obj):
    return isinstance(obj, dict) and 'id' in obj and 'type' in obj

def _iter_errors_custom(instance, checks, options):
    """Perform additional validation not possible merely with JSON schemas.

    Args:
        instance: The STIX object to be validated.
        checks: A sequence of callables which do the checks.  Each callable
            may be written to accept 1 arg, which is the object to check,
            or 2 args, which are the object and a ValidationOptions instance.
        options: ValidationOptions instance with settings affecting how
            validation should be done.
    """
    # Perform validation
    for v_function in checks:
        try:
            result = v_function(instance)
        except TypeError:
            result = v_function(instance, options)
        if isinstance(result, Iterable):
            for x in result:
                yield x
        elif result is not None:
            yield result

    # Validate any child STIX objects
    for field in instance:
        if type(instance[field]) is list:
            for obj in instance[field]:
                if _is_stix_obj(obj):
                    for err in _iter_errors_custom(obj, checks, options):
                        yield err


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


class FileValidationResults(BaseResults):
    """
    Represents validation results for a file.  This entails potentially
    several STIX object results, since a file may contain a list of STIX
    objects.
    """
    def __init__(self, is_valid=False, filepath=None, object_results=None, fatal=None):
        """
        Initialize this instance.
        :param is_valid: Whether the overall result is valid
        :param filepath: Which file was validated
        :param object_results: Individual object validation results
        :param fatal: A non-validation-related fatal error
        """
        super(FileValidationResults, self).__init__(is_valid)
        self.filepath = filepath
        self.object_results = object_results or []
        self.fatal = fatal

    def as_dict(self):
        d = super(FileValidationResults, self).as_dict()
        d.update(
            filepath=self.filepath,
            object_results=[object_result.as_dict() for object_result in self.object_results],
            fatal=self.fatal.as_dict()
        )

        return d


class ObjectValidationResults(BaseResults):
    """Results of JSON schema validation for a single STIX object.

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
    def __init__(self, is_valid=False, errors=None, warnings=None):
        super(ObjectValidationResults, self).__init__(is_valid)
        self.errors = errors
        self.warnings = warnings

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
        """A dictionary representation of the :class:`.ObjectValidationResults`
        instance.

        Keys:
            * ``'result'``: The validation results (``True`` or ``False``)
            * ``'errors'``: A list of validation errors.
        Returns:

            A dictionary representation of an instance of this class.

        """
        d = super(ObjectValidationResults, self).as_dict()

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

    results = [validate_file(fn, options) for fn in files]

    return results


def validate_parsed_json(obj_json, options=None):
    """
    Validate objects from parsed JSON.  This supports a single object, or a
    list of objects.  If a single object is given, a single result is
    returned.  Otherwise, a list of results is returned.

    If an error occurs, a ValidationErrorResults instance or list which
    includes one of these instances, is returned.

    :param obj_json: The parsed json
    :param options: Validation options
    :return: An ObjectValidationResults instance, or a list of such.
    """

    validating_list = isinstance(obj_json, list)

    if not options:
        options = ValidationOptions()

    results = None
    try:
        if validating_list:
            # Doing it this way instead of using a comprehension means that
            # initial validation results will be retained, even if a later
            # exception aborts the sequence.
            results = []
            for obj in obj_json:
                results.append(validate_instance(obj, options))
        else:
            results = validate_instance(obj_json, options)

    except SchemaInvalidError as ex:
        error_result = ObjectValidationResults(is_valid=False,
                                               errors=[str(ex)])
        if validating_list:
            results.append(error_result)
        else:
            results = error_result

    return results


def validate(in_, options=None):
    """
    Validate objects from JSON data in a textual stream.

    :param in_: A textual stream of JSON data.
    :param options: Validation options
    :return: A list of ObjectValidationResults.
    """
    obj_json = json.load(in_)

    results = validate_parsed_json(obj_json, options)

    return results


def validate_file(fn, options=None):
    """Validate the input document `fn` according to the options passed in.

    If any exceptions are raised during validation, no further validation
    will take place.

    Args:
        fn: The filename of the JSON file to be validated.
        options: An instance of ``ValidationOptions``.

    Returns:
        An instance of FileValidationResults.

    """
    file_results = FileValidationResults(filepath=fn)
    output.info("Performing JSON schema validation on %s" % fn)

    if not options:
        options = ValidationOptions(files=fn)

    try:
        with open(fn) as instance_file:
            file_results.object_results = validate(instance_file, options)

    except Exception as ex:
        if 'Expecting value' in str(ex):
            line_no = str(ex).split()[3]
            file_results.fatal = ValidationErrorResults(
                'Invalid JSON input on line %s' % line_no
            )
        else:
            file_results.fatal = ValidationErrorResults(ex)

        msg = ("Unexpected error occurred with file '{fn}'. No further "
               "validation will be performed: {error}")
        output.info(msg.format(fn=fn, error=str(ex)))

    if isinstance(file_results.object_results, list):
        file_results.is_valid = all(object_result.is_valid
                                    for object_result in file_results.object_results)
    else:
        file_results.is_valid = file_results.object_results.is_valid

    return file_results


def validate_string(string, options=None):
    """Validate the input `string` according to the options passed in.

    If any exceptions are raised during validation, no further validation
    will take place.

    Args:
        string: The string containing the JSON to be validated.
        options: An instance of ``ValidationOptions``.

    Returns:
        An instance of ObjectValidationResults.

    """
    output.info("Performing JSON schema validation on input string: " + string)
    stream = io.StringIO(string)
    return validate(stream, options)


def load_validator(schema_path, schema):
    """Create a JSON schema validator for the given schema.

    Args:
        schema_path: The filename of the JSON schema.
        schema: A Python object representation of the same schema.

    Returns:
        An instance of Draft4Validator.

    """
    # Get correct prefix based on OS
    if os.name == 'nt':
        file_prefix = 'file:///'
    else:
        file_prefix = 'file:'

    resolver = RefResolver(file_prefix + schema_path.replace("\\", "/"), schema)
    validator = Draft4Validator(schema, resolver=resolver)

    return validator


def find_schema(schema_dir, obj_type):
    """Search the `schema_dir` directory for a schema called `obj_type`.json.
    Return the file path of the first match it finds.
    """
    schema_filename = obj_type + '.json'
    for root, dirnames, filenames in os.walk(schema_dir):
        if schema_filename in filenames:
            return os.path.join(root, schema_filename)


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


def _schema_validate(sdo, options):
    """Set up validation of a single STIX object against its type's schema.
    This does no actual validation; it just returns generators which must be
    iterated to trigger the actual generation.

    Do not call this function directly; use validate_instance() instead, as it
    calls this one. This function does not perform any custom checks.
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
    sdo_validator = load_validator(sdo_schema_path, sdo_schema)
    try:
        sdo_errors = sdo_validator.iter_errors(sdo)
    except schema_exceptions.RefResolutionError:
        raise SchemaInvalidError('Invalid JSON schema: a JSON '
                                 'reference failed to resolve')

    if 'id' in sdo:
        try:
            error_prefix = sdo['id'] + ": "
        except TypeError:
            error_prefix = 'unidentifiable object: '
    else:
        error_prefix = ''
    error_gens = [(sdo_errors, error_prefix)]

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

            obj_validator = load_validator(obj_schema_path, obj_schema)
            try:
                obj_errors = obj_validator.iter_errors(obj)
            except schema_exceptions.RefResolutionError:
                raise SchemaInvalidError('Invalid JSON schema: a JSON '
                                         'reference failed to resolve')
            error_gens.append((obj_errors,
                               error_prefix + 'object \'' + key + '\': '))

    return error_gens


def validate_instance(instance, options=None):
    """Perform STIX JSON Schema validation against STIX input.

    Find the correct schema by looking at the 'type' property of the
    `instance` JSON object.

    Args:
        instance: A Python dictionary representing a STIX object with a
            'type' property.
        options: ValidationOptions instance with validation options for this
            validation run.

    Returns:
        A dictionary of validation results

    """
    if 'type' not in instance:
        raise ValidationError("Input must be an object with a 'type' property.")

    if not options:
        options = ValidationOptions()

    # Cache data from external sources; used in some checks
    if not options.no_cache:
        dirs = AppDirs("stix2-validator", "OASIS")
        # Create cache dir if doesn't exist
        try:
            os.makedirs(dirs.user_cache_dir)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise
        requests_cache.install_cache(cache_name=os.path.join(dirs.user_cache_dir, 'py{}cache'.format(sys.version_info[0])),
                                     expire_after=datetime.timedelta(weeks=1))
    if options.refresh_cache:
        now = datetime.datetime.utcnow()
        requests_cache.get_cache().remove_old_entries(now)

    error_gens = []

    # Schema validation
    if instance['type'] == 'bundle' and 'objects' in instance:
        # Validate each object in a bundle separately
        for sdo in instance['objects']:
            error_gens += _schema_validate(sdo, options)
    else:
        error_gens += _schema_validate(instance, options)

    # Custom validation
    must_checks = musts.list_musts(options)
    should_checks = shoulds.list_shoulds(options)
    output.info("Running the following additional checks: %s."
                % ", ".join(x.__name__ for x in chain(must_checks, should_checks)))
    try:
        errors = _iter_errors_custom(instance, must_checks, options)
        warnings = _iter_errors_custom(instance, should_checks, options)

        if options.strict:
            chained_errors = chain(errors, warnings)
            warnings = []
        else:
            chained_errors = errors
            warnings = [pretty_error(x, options.verbose) for x in warnings]
    except schema_exceptions.RefResolutionError:
        raise SchemaInvalidError('Invalid JSON schema: a JSON reference '
                                 'failed to resolve')

    # List of error generators and message prefixes (to denote which object the
    # error comes from)
    error_gens += [(chained_errors, '')]

    # Prepare the list of errors (this actually triggers the custom validation
    # functions).
    error_list = []
    for gen, prefix in error_gens:
        for error in gen:
            msg = prefix + pretty_error(error, options.verbose)
            error_list.append(SchemaError(msg))

    if error_list:
        valid = False
    else:
        valid = True

    # Clear requests cache if commandline flag was set
    if options.clear_cache:
        now = datetime.datetime.utcnow()
        requests_cache.get_cache().remove_old_entries(now)

    return ObjectValidationResults(is_valid=valid, errors=error_list,
                                   warnings=warnings)
