"""Custom jsonschema.IValidator class and validator functions.
"""

from collections.abc import Iterable
import copy
import functools
import io
from itertools import chain
import os
import pathlib
import re
import sys
from urllib import parse, request

from jsonschema import Draft202012Validator
from jsonschema import exceptions as schema_exceptions
from jsonschema.validators import extend
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012
import requests
import simplejson as json

from . import output
from .errors import (NoJSONFileFoundError, SchemaError, SchemaInvalidError,
                     ValidationError, pretty_error)
from .util import DEFAULT_VER, ValidationOptions
from .v20 import musts as musts20
from .v20 import shoulds as shoulds20
from .v21 import interop
from .v21 import musts as musts21
from .v21 import shoulds as shoulds21

try:
    FileNotFoundError
except NameError:
    # Python 2
    FileNotFoundError = IOError


EMAIL_RE = re.compile(r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)')


def _is_iterable_non_string(val):
    return hasattr(val, "__iter__") and not isinstance(val, str)


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
        self.object_results = object_results
        self.fatal = fatal

    def as_dict(self):
        d = super(FileValidationResults, self).as_dict()
        d.update(
            filepath=self.filepath,
            object_results=[object_result.as_dict() for object_result in self.object_results],
            fatal=self.fatal.as_dict()
        )

        return d

    @property
    def object_result(self):
        """
        Get the object result object, assuming there is only one.  Raises
        an error if there is more than one.
        :return: The result object
        :raises ValueError: If there is more than one result
        """
        num_obj_results = len(self._object_results)

        if num_obj_results < 1:
            return None
        elif num_obj_results < 2:
            return self._object_results[0]
        else:
            raise ValueError("There is more than one result; use 'object_results'")

    @object_result.setter
    def object_result(self, object_result):
        """
        Set the object result to a single value.  If ``object_result`` is not a
        single value, an error will be raised.
        :param object_result: The result to set
        :raises ValueError: if ``object_result`` is not a single value.
        """
        if _is_iterable_non_string(object_result):
            raise ValueError("Can't set \"object_result\" to more than one"
                             " result; try setting \"object_results\" instead")
        self._object_results = [object_result]

    @property
    def object_results(self):
        """
        Get all object results.
        :return: the results
        """
        return self._object_results

    @object_results.setter
    def object_results(self, object_results):
        """
        Set the results to an iterable of values.  The values will be collected
        into a list.  A single value is allowed; it will be converted to a
        length 1 list.
        :param object_results: The results to set
        """
        if _is_iterable_non_string(object_results):
            self._object_results = list(object_results)
        elif object_results is None:
            self._object_results = []
        else:
            self._object_results = [object_results]

    def log(self):
        """Print (log) these file validation results.
        """
        output.print_file_results(self)


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
        object_id: ID of the STIX object.

    """
    def __init__(self, is_valid=False, object_id=None, errors=None, warnings=None):
        super(ObjectValidationResults, self).__init__(is_valid)
        self.object_id = object_id
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

    def log(self):
        """Print (log) these file validation results.
        """
        output.print_object_results(self)


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
        self.error = str(error)
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

    for top, dirs, files in os.walk(directory):
        dirs.sort()
        # Get paths to each file in `files`
        paths = (os.path.join(top, f) for f in sorted(files))

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
    if options.files == sys.stdin:
        results = validate(options.files, options)
        return [FileValidationResults(is_valid=results.is_valid,
                                      filepath='stdin',
                                      object_results=results)]

    files = get_json_files(options.files, options.recursive)

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
    if validating_list:
        results = []
        for obj in obj_json:
            try:
                results.append(validate_instance(obj, options))
            except SchemaInvalidError as ex:
                error_result = ObjectValidationResults(is_valid=False,
                                                       object_id=obj.get('id', ''),
                                                       errors=[str(ex)])
                results.append(error_result)
    else:
        try:
            results = validate_instance(obj_json, options)
        except SchemaInvalidError as ex:
            error_result = ObjectValidationResults(is_valid=False,
                                                   object_id=obj_json.get('id', ''),
                                                   errors=[str(ex)])
            results = error_result

    return results


def validate(in_, options=None):
    """
    Validate objects from JSON data in a textual stream.

    :param in_: A textual stream of JSON data.
    :param options: Validation options
    :return: An ObjectValidationResults instance, or a list of such.
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
        with open(fn, encoding="utf-8") as instance_file:
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

    file_results.is_valid = (all(object_result.is_valid
                                 for object_result in file_results.object_results)
                             and not file_results.fatal)

    return file_results


def validate_string(string, options=None):
    """Validate the input `string` according to the options passed in.

    If any exceptions are raised during validation, no further validation
    will take place.

    Args:
        string: The string containing the JSON to be validated.
        options: An instance of ``ValidationOptions``.

    Returns:
        An ObjectValidationResults instance, or a list of such.

    """
    output.info("Performing JSON schema validation on input string: " + string)
    stream = io.StringIO(string)
    return validate(stream, options)


STIXValidator = extend(Draft202012Validator)


# Built-in checker only ensures emails contain an '@'; we want a more robust check
@Draft202012Validator.FORMAT_CHECKER.checks('email')
def is_email(instance):
    if not isinstance(instance, str):
        return True
    return EMAIL_RE.match(instance)


def from_uri_to_path(uri: str) -> str:
    """Convert a URI to a file path if possible.

    Note: replace with 'Path.from_uri(schema_path_uri)' when Python 3.13.

    Args:
        uri: the URI, potentially containing a file path.

    Returns:
        The file path if the URI contains a file path, the URI otherwise.
    """
    parsed_url = parse.urlparse(uri)
    if parsed_url.scheme == "file":
        return request.url2pathname(parsed_url.path)
    else:
        return uri


def patch_schema(schema_data: dict, schema_path: str) -> dict:
    """Patch schemas with two important fixes.

    1) _SPECIFICATIONS dictionary inside referencing.jsonschema is a mapping
        between URLs and validators; 'DRAFT201909' and 'DRAFT202012' are now
        only recognized as such if the URLs is https://.

    2) For relative references to work, the $id of the schema needs to point
        to a valid URI or path, that can later be used as a key to retrieve
        a loaded resource.

    Args:
        schema_data: the schema itself.
        schema_path: the path of the schema (can be both URI or path).

    Returns:
        The patched schema.
    """
    schema_data = copy.copy(schema_data)
    if "$schema" in schema_data:
        schema_data["$schema"] = schema_data["$schema"].replace(
            "http://json-schema.org/draft/", "https://json-schema.org/draft/"
        )
    if "$id" in schema_data:
        schema_path = pathlib.Path(schema_path)
        if schema_path.is_absolute():
            schema_data["$id"] = str(schema_path.as_uri())
        else:
            schema_data["$id"] = str(schema_path)
    return schema_data


_HTTP_SCHEMAS = dict()


_FILE_SCHEMAS = dict()


def retrieve_from_filesystem(schema_path_uri: str, schema_dir: str) -> Resource:
    """Callback to retrieve a schema given its path.

    Args:
        schema_path_uri: the schema URI.
        schema_dir: the optional directory of local schemas.

    Returns:
        A resource loaded with the content.
    """
    if schema_path_uri.startswith("http://") or schema_path_uri.startswith("https://"):
        if schema_path_uri in _HTTP_SCHEMAS:
            return _HTTP_SCHEMAS[schema_path_uri]
        response = requests.get(schema_path_uri, allow_redirects=True)
        schema = response.json()
        schema = patch_schema(schema, schema_path_uri)
        schema_resource = Resource.from_contents(schema)
        _HTTP_SCHEMAS[schema_path_uri] = schema_resource
        return schema_resource
    else:
        if schema_path_uri in _FILE_SCHEMAS:
            return _FILE_SCHEMAS[schema_path_uri]
        schema_path = pathlib.Path(schema_path_uri)
        if schema_path.is_absolute() or schema_path_uri.startswith("file://"):
            is_relative = False
            schema_path = from_uri_to_path(schema_path_uri)
        else:
            is_relative = True
            schema_path = from_uri_to_path(os.path.join(schema_dir, schema_path_uri))
        with open(schema_path, "r") as f:
            schema = json.load(f)
        schema = patch_schema(schema, schema_path)
        if is_relative:
            schema_resource = Resource.opaque(schema)
        else:
            schema_resource = Resource.from_contents(schema)
        _FILE_SCHEMAS[schema_path_uri] = schema_resource
        return schema_resource


_PATCHED_SCHEMAS = dict()


def load_validator(schema_path, schema, schema_dir):
    """Create a JSON schema validator for the given schema.

    Args:
        schema_path: The filename of the JSON schema.
        schema: A Python object representation of the same schema.

    Returns:
        An instance of Draft202012Validator.
    """
    if schema_path in _PATCHED_SCHEMAS:
        schema = _PATCHED_SCHEMAS[schema_path]
    else:
        schema = patch_schema(schema, schema_path)
        _PATCHED_SCHEMAS[schema_path] = schema
    retrieve_callback = functools.partial(retrieve_from_filesystem, schema_dir=schema_dir)
    registry = Registry(
        retrieve=retrieve_callback
    ).with_resource(schema_path, DRAFT202012.create_resource(schema))
    validator = STIXValidator(schema,  registry=registry, format_checker=Draft202012Validator.FORMAT_CHECKER)
    return validator


_SCHEMAS_FOUND = dict()


def find_schema(schema_dir, name):
    """Search the `schema_dir` directory for a schema called `name`.json.
    Return the file path of the first match it finds.
    """
    if schema_dir in _SCHEMAS_FOUND and name in _SCHEMAS_FOUND[schema_dir]:
        return _SCHEMAS_FOUND[schema_dir][name]

    schema_filename = name + '.json'

    for root, dirnames, filenames in os.walk(schema_dir, followlinks=True):
        if "examples" in root:
            continue
        if schema_filename in filenames:
            schema_path = os.path.join(root, schema_filename)
            if schema_dir not in _SCHEMAS_FOUND:
                _SCHEMAS_FOUND[schema_dir] = dict()
            _SCHEMAS_FOUND[schema_dir][name] = schema_path
            return schema_path


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


def _get_error_generator(name, obj, schema_dir=None, version=DEFAULT_VER, default='core'):
    """Get a generator for validating against the schema for the given object type.

    Args:
        name (str): The object type or extension id to find the schema for.
        obj: The object to be validated.
        schema_dir (str): The path in which to search for schemas.
        version (str): The version of the STIX specification to validate
            against. Only used to find base schemas when schema_dir is None.
        default (str): If the schema for the given type cannot be found, use
            the one with this name instead.

    Returns:
        A generator for errors found when validating the object against the
        appropriate schema, or None if schema_dir is None and the schema
        cannot be found.
    """
    # If no schema directory given, use default for the given STIX version,
    # which comes bundled with this package
    default_path = False
    if schema_dir is None:
        default_path = True
        schema_dir = os.path.abspath(os.path.dirname(__file__) + '/schemas-'
                                     + version + '/schemas/')

    try:
        schema_path = find_schema(schema_dir, name)
        schema = load_schema(schema_path)
    except (KeyError, TypeError):
        # Assume a custom object or extension with no schema
        try:
            schema_path = find_schema(schema_dir, default)
            schema = load_schema(schema_path)
        except (KeyError, TypeError):
            # Only raise an error when checking against default schemas, not custom
            if default_path is False:
                if 'extension-definition--' in name:
                    output.info("Could not find schema for {} so it will only be validated against the default schema.".format(name))
                return None

            if schema_path is None:
                raise SchemaInvalidError("Cannot locate a schema for the object's "
                                         "type, nor the base schema ({}.json).".format(default))

    if 'extension-definition--' in name and schema_path:
        output.info("Validating {} against {}".format(name, schema_path))

    type = obj['type']
    if type == 'observed-data' and schema_dir is None:
        # Validate against schemas for specific observed data object types later.
        # If schema_dir is not None the schema is custom and won't need to be modified.
        schema['allOf'][1]['properties']['objects'] = {
            "objects": {
                "type": "object",
                "minProperties": 1
            }
        }
    elif type == 'bundle':
        # Validate against schemas for specific objects later
        schema['properties']['objects'] = {
            "objects": {
                "type": "array",
                "minItems": 1
            }
        }

    # Don't use custom validator; only check schemas, no additional checks
    validator = load_validator(schema_path, schema, schema_dir)
    try:
        error_gen = validator.iter_errors(obj)
    except schema_exceptions.RefResolutionError:
        raise SchemaInvalidError('Invalid JSON schema: a JSON '
                                 'reference failed to resolve')
    return error_gen


def _get_musts(options):
    """Return the list of 'MUST' validators for the correct version of STIX.

    Args:
        options: ValidationOptions instance with validation options for this
            validation run, including the STIX spec version.
    """
    if options.version == '2.0':
        return musts20.list_musts(options)
    else:
        return musts21.list_musts(options)


def _get_shoulds(options):
    """Return the list of 'SHOULD' validators for the correct version of STIX.

    Args:
        options: ValidationOptions instance with validation options for this
            validation run, including the STIX spec version.
    """
    if options.version == '2.0':
        return shoulds20.list_shoulds(options)
    else:
        return shoulds21.list_shoulds(options)


def find_version(obj, options, bundle_version=None, error_prefix=''):
    if options.version:
        version = options.version
    elif options.version is None and 'spec_version' in obj:
        version = obj['spec_version']
    else:
        version = DEFAULT_VER

    if bundle_version == '2.0':
        version = bundle_version

    # Allow 2.0 objects in 2.1+ bundles (2.1 SCOs don't have 'created')
    _20_in_21_bundle = (bundle_version == '2.1' and 'spec_version' not in obj and
                        'created' in obj)
    if _20_in_21_bundle:
        version = '2.0'
        output.info("%sno spec_version so treated as a 2.0 object in a 2.1 bundle."
                    % error_prefix)

    return version


def _schema_validate(obj, options, bundle_version=None):
    """Set up validation of a single STIX object against its type's schema.
    This does no actual validation; it just returns generators which must be
    iterated to trigger the actual generation.

    This function first creates generators for the built-in schemas, then adds
    generators for additional schemas from the options, if specified.

    Do not call this function directly; use validate_instance() instead, as it
    calls this one. This function does not perform any custom checks.

    Args:
        obj: STIX object to validate.
        options: ValidationOptions instance with validation options for this
            validation run, including the STIX spec version.
        bundle_version: STIX version of the bundle containing this object, or
            None if the object is not inside a bundle or the bundle has no
            spec_version property.
    """
    error_gens = []
    if 'id' in obj:
        try:
            error_prefix = obj['id'] + ": "
        except TypeError:
            error_prefix = 'unidentifiable object: '
    else:
        error_prefix = ''

    version = find_version(obj, options, bundle_version, error_prefix)

    options.set_check_codes(version)

    core_schema = 'core'
    # Check for custom 2.1+ SCO
    if (version > '2.0' and all(p in obj for p in ['type', 'id']) and
            all(p not in obj for p in ['created', 'modified']) and
            not obj['type'] == 'marking-definition'):
        core_schema = 'cyber-observable-core'

    # Get validator for built-in schema
    base_sdo_errors = _get_error_generator(obj['type'], obj, version=version, default=core_schema)
    if base_sdo_errors:
        error_gens.append((base_sdo_errors, error_prefix))

    # Get validator for interop schemas if needed
    if options.interop and version != '2.0':
        interop_schema_dir = os.path.abspath(os.path.dirname(__file__) + '/schemas-'
                                             + version + '/interop/')
        interop_errors = _get_error_generator(obj['type'], obj, interop_schema_dir, version, default=core_schema)
        if interop_errors:
            error_gens.append((interop_errors, error_prefix))

    # Get validators for any user-supplied schema
    if options.schema_dir:
        # schemas named by object type
        custom_sdo_errors = _get_error_generator(obj['type'], obj, options.schema_dir, version, default=core_schema)
        if custom_sdo_errors:
            error_gens.append((custom_sdo_errors, error_prefix))

        # schemas for extensions
        extension_ids = obj.get('extensions', dict()).keys()
        for ext in extension_ids:
            extension_errors = _get_error_generator(ext, obj, options.schema_dir, version, default=core_schema)
            if extension_errors:
                error_gens.append((extension_errors, error_prefix))
    elif options.verbose and obj.get('extensions'):
        keys = obj.get('extensions', {}).keys()
        if any(key.startswith('extension-definition--') for key in keys):
            output.info("{} contains extensions but no additional schemas provided "
                        "with the --schemas option.".format(obj['id']))

    # Validate each cyber observable object separately
    if obj['type'] == 'observed-data' and 'objects' in obj:
        # Check if observed data property is in dictionary format
        if not isinstance(obj['objects'], dict):
            error_gens.append(([schema_exceptions.ValidationError("Observed Data objects must be in dict format.", error_prefix)],
                              error_prefix))
            return error_gens

        for key, val in obj['objects'].items():
            if 'type' not in val:
                error_gens.append(([schema_exceptions.ValidationError("Observable object must contain a 'type' property.", error_prefix)],
                                   error_prefix + 'object \'' + key + '\': '))
                continue
            # Get validator for built-in schemas
            base_obs_errors = _get_error_generator(val['type'],
                                                   val,
                                                   None,
                                                   version,
                                                   'cyber-observable-core')
            if base_obs_errors:
                error_gens.append((base_obs_errors,
                                   error_prefix + 'object \'' + key + '\': '))

            # Get validator for any user-supplied schema
            if options.schema_dir:
                custom_obs_errors = _get_error_generator(val['type'],
                                                         val,
                                                         options.schema_dir,
                                                         version,
                                                         'cyber-observable-core')
                if custom_obs_errors:
                    error_gens.append((custom_obs_errors,
                                       error_prefix + 'object \'' + key + '\': '))

    return error_gens


def _schema_validate_bundle(instance, options):
    errors = []
    version = options.version
    if version is None and 'spec_version' in instance:
        version = instance['spec_version']

    warnings = []
    if version:
        if 'spec_version' in instance:
            if instance['spec_version'] != version:
                warnings.append(instance['id'] + ": spec_version mismatch with supplied"
                                " option. Treating as {} content.".format(version))
        if 'objects' in instance:
            for obj in instance['objects']:
                if 'spec_version' in obj:
                    if obj['spec_version'] != version:
                        warnings.append(obj['id'] + ": spec_version mismatch with supplied"
                                        " option. Treating as {} content.".format(version))

    bundle_version = instance.get('spec_version', '2.1')
    # Validate each object in a bundle separately
    for sdo in instance.get('objects', []):
        if 'type' not in sdo:
            raise ValidationError("Each object in bundle must have a 'type' property.")
        errors += _schema_validate(sdo, options, bundle_version)

    return errors, warnings


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
    if not _is_stix_obj(instance):
        raise ValidationError("Input must be an object with 'id' and 'type' properties.")

    if not options:
        options = ValidationOptions()

    error_gens = []
    spec_warnings = []

    # Schema validation
    error_gens += _schema_validate(instance, options)
    if instance['type'] == 'bundle' and 'objects' in instance:
        schema_errors, spec_warnings = _schema_validate_bundle(instance, options)
        error_gens += schema_errors

    # Custom validation
    must_checks = _get_musts(options)
    version = find_version(instance, options)
    if options.interop is True and version != '2.0':
        must_checks.append(interop.interop_created_by_ref)
    should_checks = _get_shoulds(options)
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
            warnings.extend(spec_warnings)
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
    if options.strict:
        error_list.extend(spec_warnings)
    if error_list:
        valid = False
    else:
        valid = True
    return ObjectValidationResults(is_valid=valid, object_id=instance.get('id', ''),
                                   errors=error_list, warnings=warnings)
