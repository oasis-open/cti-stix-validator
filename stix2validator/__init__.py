
# builtin
import os
import json
from itertools import chain
import fnmatch
import re

# external
from jsonschema import RefResolver
from jsonschema import exceptions as schema_exceptions
from six import python_2_unicode_compatible, text_type

# internal
from . import output
from . import enums
from .validators import ValidationOptions, CustomDraft4Validator


class ValidationError(Exception):
    """Base Exception for all validator-specific exceptions. This can be used
    directly as a generic Exception.
    """
    pass


class SchemaInvalidError(ValidationError):
    """Represents an error with the JSON Schema file itself.

    """
    def __init__(self, msg=None, results=None):
        super(SchemaInvalidError, self).__init__(msg)
        if not results:
            self.results = ValidationErrorResults(self)
        else:
            self.results = results


@python_2_unicode_compatible
class SchemaError(ValidationError):
    """Represents a JSON Schema validation error.

    Args:
        error: An error returned from JSON Schema validation.

    Attributes:
        message: The JSON validation error message.

    """
    def __init__(self, error):
        super(SchemaError, self).__init__()

        if error:
            self.message = text_type(error)
        else:
            self.message = None

    def as_dict(self):
        """Returns a dictionary representation.
        """
        return {'message': self.message}

    def __str__(self):
        return text_type(self.message)


def pretty_error(error, verbose=False):
    """Returns an error message that is easier to read and more useful.
    """
    import logging
    error_loc = ''
    try:
        error_loc = error.instance['id'] + ': '
    except (TypeError, KeyError):
        if error.path:
            while len(error.path) > 0:
                path_elem = error.path.popleft()
                if type(path_elem) is not int:
                    error_loc += path_elem
                elif len(error.path) > 0:
                    error_loc += '[' + text_type(path_elem) + ']/'
            error_loc += ': '

    # Get error message and remove ugly u'' prefixes
    if verbose:
        msg = text_type(error)
    else:
        msg = error.message
    msg = re.sub(r"(^| )(|\[|\(|\{)u'", r"\g<1>\g<2>'", msg)

    # Don't reword error messages from our validators,
    # only the default error messages from the jsonschema library
    if repr(error.schema) == '<unset>':
        return error_loc + msg

    # Reword error messages containing regexes
    if error.validator == 'pattern' and 'title' in error.schema:
        if error.schema['title'] == 'type':
            msg = re.sub(r"match '.+'$", 'match the \'type\' field format '
                         '(lowercase ASCII a-z, 0-9, and hypens only - and no '
                         'two hyphens in a row)', msg)
        elif error.schema['title'] == 'identifier':
            msg = re.sub(r"match '.+'$", 'match the id format '
                         '([object-type]--[UUIDv4])', msg)
        elif error.schema['title'] == 'id':
            msg = re.sub(r"match '.+'$", 'start with \'' +
                         error.validator_value[1:-2] + '--\'', msg)
        elif error.schema['title'] == 'timestamp':
            msg = re.sub(r"match '.+'$", 'match the timestamp format '
                         '(YYYY-MM-DDTHH:mm:ss[.s+]Z)', msg)
        elif error.schema['title'] == 'relationship_type':
            msg = re.sub(r"does not match '.+'$", 'contains invalid '
                         'characters', msg)
        elif error.schema['title'] == 'url':
            msg = re.sub(r"match '.+'$", 'match the format '
                         'of a URL', msg)
    # Reword 'is not valid under any of the given schemas' errors
    elif type(error.instance) is list and len(error.instance) == 0:
        msg = re.sub(r"\[\] is not valid .+$", 'empty arrays are not allowed',
                     msg)
    # Reword custom property errors
    elif 'title' in error.schema and error.schema['title'] == 'core':
        if error.validator == 'additionalProperties':
            msg = re.sub(r"Additional .+$", 'Custom properties must match the '
                         'proper format (lowercase ASCII a-z, 0-9, and '
                         'underscores; 3-250 characters)', msg)
        elif error.validator == 'not' and 'anyOf' in error.validator_value:
            msg = re.sub(r".+", "Contains a reserved property ('%s')"
                         % "', '".join(enums.RESERVED_PROPERTIES), msg)
    # Reword external reference error
    elif error.validator == 'oneOf':
        if 'external_references' in error.schema_path:
            msg = "If the external reference is a CVE, 'source_name' must be" \
                  " 'cve' and 'external_id' must be in the CVE format " \
                  "(CVE-YYYY-NNNN+). If the external reference is a CAPEC, " \
                  "'source_name' must be 'capec' and 'external_id' must be " \
                  "in the CAPEC format (CAPEC-N+)."
    # Reword forbidden enum value errors
    elif error.validator == 'not':
        if 'enum' in error.validator_value:
            msg = re.sub(r"\{.+\} is not allowed for '(.+)'$", r"'\g<1>' is "
                         "not an allowed value", msg)
        elif ('target_ref' in error.schema_path or
                    'source_ref' in error.schema_path):
                msg = ("Relationships cannot link bundles, marking definitions"
                       ", sightings, or other relationships. This field must "
                       "contain the id of an SDO.")

    return error_loc + msg



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
        """Returns a dictionary representation of this class.

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
        fn: The filename/path for the file that was validated; None if a string
            was validated.

    Attributes:
        is_valid: ``True`` if the validation was successful and ``False``
            otherwise.

    """
    def __init__(self, is_valid=False, errors=None, fatal=None, fn=None):
        super(ValidationResults, self).__init__(is_valid)
        self.errors = errors
        self.fatal = fatal
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
    """Returns a list of file paths for JSON files within `directory`.

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
    """Returns a list of files to validate from `files`. If a member of `files`
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

    return json_files



def run_validation(options):
    """Validates files based on command line options.

    Args:
        options: An instance of ``ValidationOptions`` containing options for
            this validation run.

    """
    # The JSON files to validate
    files = get_json_files(options.files, options.recursive)

    results = {}
    for fn in files:
        results[fn] = validate_file(fn, options)

    return results


def validate_file(fn, options=None):
    """Validates the input document `fn` according to the options passed in.

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

    with open(fn) as instance_file:
        instance = json.load(instance_file)

    if not options:
        options = ValidationOptions(files=fn)

    try:
        if options.files:
            results = schema_validate(instance, options)
    except SchemaInvalidError as ex:
        results.fatal = ValidationErrorResults(ex)
        msg = ("File '{fn}' was schema-invalid. No further validation "
               "will be performed.")
        output.info(msg.format(fn=fn))
    except Exception as ex:
        results.fatal = ValidationErrorResults(ex)
        msg = ("Unexpected error occurred with file '{fn}'. No further "
               "validation will be performed: {error}")
        output.info(msg.format(fn=fn, error=str(ex)))

    if results.errors or results.fatal:
        results.is_valid = False

    return results


def validate_string(string, options=None):
    """Validates the input `string` according to the options passed in.

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


def load_validator(schema_path, schema, options):
    """Creates a JSON schema validator for the given schema.

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
    validator = CustomDraft4Validator(schema, resolver=resolver, options=options)

    return validator


def find_schema(schema_dir, obj_type):
    """Searches the `schema_dir` directory for a schema called `obj_type`.json.
    Returns the file path of the first match it finds.
    """
    for root, dirnames, filenames in os.walk(schema_dir):
        for filename in fnmatch.filter(filenames, obj_type + '.json'):
            return os.path.join(root, filename)


def load_schema(schema_path):
    """Loads the JSON schema at the given path as a Python object.

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


def schema_validate(instance, options):
    """Performs STIX JSON Schema validation against the input JSON.
    Finds the correct schema by looking at the 'type' property of the
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
    except (KeyError, TypeError) as e:
        # Assume a custom object with no schema
        try:
            schema_path = find_schema(options.schema_dir, 'core')
            schema = load_schema(schema_path)
        except (KeyError, TypeError) as e:
            raise SchemaInvalidError("Cannot locate a schema for the object's "
                                     "type, nor the base schema (core.json).")

    # Validate the schema first
    try:
        CustomDraft4Validator.check_schema(schema)
    except schema_exceptions.SchemaError as e:
        raise SchemaInvalidError('Invalid JSON schema: ' + str(e))

    validator = load_validator(schema_path, schema, options)
    output.info("Running the following additional checks: %s."
                % ", ".join(x.__name__ for x in validator.validator_list))

    # Actual validation of JSON document
    try:
        some_errors = validator.iter_errors(instance)
        more_errors = validator.iter_errors_more(instance)
        chained_errors = chain(some_errors, more_errors)
        errors = sorted(chained_errors, key=lambda e: e.path)
    except schema_exceptions.RefResolutionError:
        raise SchemaInvalidError('Invalid JSON schema: a JSON reference '
                                 'failed to resolve')

    if len(errors) == 0:
        return ValidationResults(True)

    # Prepare the list of errors
    error_list = []
    for error in errors:
        msg = pretty_error(error, options.verbose)
        error_list.append(SchemaError(msg))

    return ValidationResults(False, error_list)
