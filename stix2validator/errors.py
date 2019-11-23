from collections import deque
import re

from jsonschema import exceptions as schema_exceptions
from six import python_2_unicode_compatible, text_type


class PatternError(schema_exceptions.ValidationError):
    """Represent a problem with a STIX Pattern.
    """
    def __init__(self, msg=None, instance_id=None):
        msg = 'Pattern failed to validate: %s.' % msg
        super(PatternError, self).__init__(msg, path=deque([instance_id]))


class NoJSONFileFoundError(OSError):
    """Represent a problem finding the input JSON file(s).

    """
    pass


class ValidationError(Exception):
    """Base Exception for all validator-specific exceptions. This can be used
    directly as a generic Exception.
    """
    pass


class SchemaInvalidError(ValidationError):
    """Represent an error with the JSON Schema file itself.

    """
    pass


@python_2_unicode_compatible
class SchemaError(ValidationError):
    """Represent a JSON Schema validation error.

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


def remove_u(input):
    """Remove ugly u'' prefixes from input string
    """
    return re.sub(r"(^| )(|\[|\(|\{|\[\{)u'", r"\g<1>\g<2>'", input)


def pretty_error(error, verbose=False):
    """Return an error message that is easier to read and more useful.
    May require updating if the schemas change significantly.
    """
    error_loc = ''

    if error.path:
        while len(error.path) > 0:
            path_elem = error.path.popleft()
            if type(path_elem) is not int:
                if error_loc:
                    error_loc += '.'
                error_loc += path_elem
            # elif len(error.path) > 0:
            else:
                error_loc += '[' + text_type(path_elem) + ']'
        error_loc += ': '

    # Get error message and remove ugly u'' prefixes
    if verbose:
        msg = remove_u(text_type(error))
    else:
        msg = remove_u(error.message)

    # Don't reword error messages from our validators,
    # only the default error messages from the jsonschema library
    if repr(error.schema) == '<unset>':
        try:
            return error_loc + msg
        except UnicodeDecodeError:
            return error_loc + msg.decode('utf-8')

    # Reword error messages containing regexes
    if error.validator == 'pattern' and 'title' in error.schema:
        if error.schema['title'] == 'type':
            msg = re.sub(r"match '.+'$", 'match the \'type\' field format '
                         '(lowercase ASCII a-z, 0-9, and hypens only - and no '
                         'two hyphens in a row)', msg)
        elif error.schema['title'] == 'identifier':
            msg = re.sub(r"match '.+'$", 'match the id format '
                         '([object-type]--[UUID])', msg)
        elif error.schema['title'] == 'id':
            msg = re.sub(r"match '.+'$", 'start with \'' +
                         error.validator_value[1:-2] + '--\'', msg)
        elif error.schema['title'] == 'timestamp':
            msg = re.sub(r"match '.+'$", 'match the timestamp format '
                         'YYYY-MM-DDTHH:mm:ss[.s+]Z', msg)
        elif error.schema['title'] == 'timestamp_millis':
            msg = re.sub(r"match '.+'$", 'match the timestamp format '
                         'YYYY-MM-DDTHH:mm:ss.sssZ (must be precise to the '
                         'millisecond)', msg)
        elif error.schema['title'] == 'relationship_type':
            msg = re.sub(r"does not match '.+'$", 'contains invalid '
                         'characters', msg)
        elif error.schema['title'] == 'url-regex':
            msg = re.sub(r'match ".+"$', 'match the format '
                         'of a URL', msg)
        elif error.schema['title'] == 'binary':
            msg = re.sub(r"does not.+'$", 'must be a base64-encoded string', msg)
    elif error.validator == 'pattern' and 'observed_data_refs' in error.schema_path:
        msg = "'observed_data_refs' must refer to Observed Data Objects"
    elif error.validator == 'pattern' and 'where_sighted_refs' in error.schema_path:
        msg = "'where_sighted_refs' must refer to Identity Objects"

    # Reword empty array errors
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
            reserved_properties = [y for x in error.validator_value['anyOf'] for y in x['required']]
            msg = re.sub(r".+", "Contains a reserved property ('%s')"
                         % "', '".join(reserved_properties), msg)
    elif 'title' in error.schema and error.schema['title'] == 'cyber-observable-core':
        if error.validator == 'additionalProperties':
            msg = re.sub(r"Additional .+$", 'Custom observable properties must'
                         ' match the proper format (lowercase ASCII a-z, 0-9, '
                         'and underscores; 3-250 characters)', msg)

    elif error.validator == 'additionalProperties':
        if 'extensions' in error.schema_path:
            msg = re.sub(r"Additional .+$", 'Custom extension keys may only '
                         'contain alphanumeric characters, dashes, and '
                         'underscores; 3-256 characters', msg)

    # Reword 'is valid under each of' errors
    elif error.validator == 'oneOf':
        try:
            if 'external_references' in error.schema_path:
                msg = "If the external reference is a CVE, 'source_name' must be" \
                      " 'cve' and 'external_id' must be in the CVE format " \
                      "(CVE-YYYY-NNNN+). If the external reference is a CAPEC, " \
                      "'source_name' must be 'capec' and 'external_id' must be " \
                      "in the CAPEC format (CAPEC-N+). If the external reference "\
                      "is neither, it must contain the 'source_name' property and"\
                      " at least one of the 'external_id', 'url', or "\
                      "'description' properties."
            elif 'type' in error.instance and error.instance['type'] == 'email-message':
                if 'is_multipart' not in error.instance:
                    msg = "'is_multipart' is a required property"
                elif error.instance['is_multipart'] is True:
                    msg = "Since 'is_multipart' is true, 'body_multipart' must "\
                          "contain valid 'mime-part-type' objects and the 'body' "\
                          "property must not be present. "
                elif error.instance['is_multipart'] is False:
                    msg = "Since 'is_multipart' is false, 'body' must be a string"\
                          " and the 'body_multipart' property must not be present."
            elif 'type' in error.instance and error.instance['type'] == 'artifact':
                if 'payload_bin' in error.instance and 'url' in error.instance:
                    msg = "'artifact' object must contain either 'payload_bin' "\
                          "or 'url' but not both"
                elif 'payload_bin' in error.instance:
                    msg = "'payload_bin' must be base64 encoded and 'hashes', if "\
                          "present, must contain a valid dictionary of hashes"
                elif 'url' in error.instance:
                    msg = "'url' must be a valid url and 'hashes', which must be "\
                          "present, must contain a valid hash dictionary"
                else:
                    msg = "'artifact' object must contain either 'payload_bin' "\
                          "or 'url'"
            elif 'type' in error.instance and error.instance['type'] == 'marking-definition':
                msg = "'definition' must contain a valid statement, TLP, or "\
                      "custom marking definition"
            elif 'type' in error.instance and error.instance['type'] == 'file':
                if (('is_encrypted' not in error.instance or
                        error.instance['is_encrypted'] is False) and
                        ('encryption_algorithm' in error.instance or
                         'decryption_key' in error.instance)):
                    msg = "'file' objects may only contain 'encryption_algorithm'"\
                          " or 'decryption_key' when 'is_encrypted' is true"
            elif 'type' in error.instance and error.instance['type'] == 'network-traffic':
                if ('is_active' in error.instance and
                        error.instance['is_active'] is True and
                        'end' in error.instance):
                    msg = "If the 'is_active' property is true, then the "\
                          "'end' property must not be included."
            else:
                raise TypeError
        except TypeError:
            msg = msg + ':\n' + remove_u(text_type(error.schema))

    # Reword forbidden property or value errors
    elif error.validator == 'not':
        if 'enum' in error.validator_value:
            msg = re.sub(r"\{.+\} is not allowed for '(.+)'$", r"'\g<1>' is "
                         "not an allowed value", msg)
        elif ('target_ref' in error.schema_path or
              'source_ref' in error.schema_path):
            msg = "Relationships cannot link bundles, marking definitions"\
                    ", sightings, or other relationships. This field must "\
                    "contain the id of an SDO."
        elif 'sighting_of_ref' in error.schema_path:
            msg = "'sighting_of_ref' must refer to a STIX Domain Object or "\
                  "Custom Object"

    # Reword 'is not valid under any of the given schemas' errors
    elif error.validator == 'anyOf':
        try:
            if error.instance == {}:
                msg = "must contain at least one property from this type."
            elif error.instance is None:
                msg = "null properties are not allowed in STIX."
            elif 'type' in error.instance and error.instance['type'] == 'network-traffic':
                if ('src_ref' not in error.instance and
                        'dst_ref' not in error.instance):
                    msg = "'network-traffic' objects must contain at least "\
                          "one of 'src_ref' or 'dst_ref'"
            elif 'type' in error.instance and error.instance['type'] in ['process', 'x509-certificate']:
                if error.instance.keys() == ['type']:
                    msg = "must contain at least one property (other than `type`) from this object."
            elif "'not': {'enum':" in text_type(error.validator_value):
                try:
                    defined_objs = error.validator_value[1]['allOf'][1]['properties']['type']['not']['enum']
                    if error.instance['type'] in defined_objs:
                        # Avoid long 'is not valid under any of the given schemas' message
                        # when object doesn't match the schema for its spec-defined type.
                        # Real error will show up as separate error.
                        msg = '{} is not a valid {} object'.format(error.instance, error.instance['type'])
                except KeyError:
                    raise TypeError
            else:
                raise TypeError
        except TypeError:
            msg = msg + ':\n' + remove_u(text_type(error.schema))

    return error_loc + msg
