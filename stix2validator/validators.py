"""Custom jsonschema.IValidator class and validator functions.
"""

# builtin
import os
import re
from collections import deque, Iterable

# external
from jsonschema import Draft4Validator
from jsonschema import exceptions as schema_exceptions

# internal
from . import enums


class ValidationOptions(object):
    """Collection of validation options which can be set via command line or
    programmatically in a script.

    It can be initialized either by passing in the result of parse_args() from
    argparse to the cmd_args parameter, or by specifying individual options
    with the other parameters.

    Attributes:
        cmd_args: An instance of ``argparse.Namespace`` containing options
            supplied on the command line.
        verbose: True if informational notes and more verbose error messages
            should be printed to stdout/stderr.
        files: A list of input files and directories of files to be
            validated.
        recursive: Recursively descend into input directories.
        schema_dir: A user-defined schema directory to validate against.
        disabled: List of "SHOULD" checks that will be skipped.
        enabled: List of "SHOULD" checks that will be performed.
        strict: Specifies that recommended requirements should produce errors
            instead of mere warnings.
        strict_types: Specifies that no custom object types be used, only
            those detailed in the STIX specification.

    """
    def __init__(self, cmd_args=None, verbose=False, files=None,
                 recursive=False, schema_dir=None, disabled="",
                 enabled="", strict=False, strict_types=False):
        if cmd_args is not None:
            self.verbose = cmd_args.verbose
            self.files = cmd_args.files
            self.recursive = cmd_args.recursive
            self.schema_dir = cmd_args.schema_dir
            self.disabled = cmd_args.disabled
            self.enabled = cmd_args.enabled
            self.strict = cmd_args.strict
            self.strict_types = cmd_args.strict_types
        else:
            # input options
            self.files = files
            self.recursive = recursive
            self.schema_dir = schema_dir

            # output options
            self.verbose = verbose
            self.strict = strict
            self.strict_types = strict_types
            self.disabled = disabled
            self.enabled = enabled

        # If no schema directory given, use default bundled with this package
        if not self.schema_dir:
            self.schema_dir = os.path.abspath(os.path.dirname(__file__) +
                                              '/schemas/')

        # Convert string of comma-separated checks to a list,
        # and convert check code numbers to names
        if self.disabled:
            self.disabled = self.disabled.split(",")
            self.disabled = [CHECK_CODES[x] if x in CHECK_CODES else x
                                   for x in self.disabled]
        if self.enabled:
            self.enabled = self.enabled.split(",")
            self.enabled = [CHECK_CODES[x] if x in CHECK_CODES else x
                                   for x in self.enabled]


class JSONError(schema_exceptions.ValidationError):
    """Wrapper for errors thrown by iter_errors() in the jsonschema module.
    """
    def __init__(self, msg=None, instance_id=None, check_code=None):
        if check_code is not None:
            # Get code number code from name
            code = list(CHECK_CODES.keys())[list(CHECK_CODES.values()).index(check_code)]
            msg = '{%s} %s' % (code, msg)
        super(JSONError, self).__init__(msg, path=deque([instance_id, 0]))


# Checks for MUST Requirements

def modified_created(instance):
    """`modified` property must be later or equal to `created` property
    """
    if 'modified' in instance and 'created' in instance and \
            instance['modified'] < instance['created']:
        return JSONError("'modified' (%s) must be later or equal to 'created' (%s)"
            % (instance['modified'], instance['created']), instance['id'])


def version(instance):
    """Check constraints on 'version' property
    """
    if 'version' in instance and 'modified' in instance and \
            'created' in instance:
        if instance['version'] == 1 and instance['modified'] != instance['created']:
            return JSONError("'version' is 1, but 'created' (%s) is not "
                "equal to 'modified' (%s)"
                % (instance['created'], instance['modified']), instance['id'])
        elif instance['version'] > 1 and instance['modified'] <= instance['created']:
            return JSONError("'version' is greater than 1, but 'modified'"
                " (%s) is not greater than 'created' (%s)" 
                % (instance['modified'], instance['created']), instance['id'])


def timestamp_precision(instance):
    """Ensure that for every precision property there is a matching timestamp
    property that uses the proper timestamp format for the given precision.
    """
    for prop_name in instance.keys():
        precision_matches = re.match("^(.*)_precision$", prop_name)
        if not precision_matches:
            continue

        ts_field = precision_matches.group(1)
        if ts_field not in instance:
            yield JSONError("There is no corresponding '%s' field for %s"
                            % (ts_field, prop_name), instance['id'])
        else:
            pattern = ""
            if instance[prop_name] == 'year':
                pattern = "^[0-9]{4}-01-01T00:00:00(\\.0+)?Z$"
            elif instance[prop_name] == 'month':
                pattern = "^[0-9]{4}-[0-9]{2}-01T00:00:00(\\.0+)?Z$"
            elif instance[prop_name] == 'day':
                pattern = "^[0-9]{4}-[0-9]{2}-[0-9]{2}T00:00:00(\\.0+)?Z$"
            elif instance[prop_name] == 'hour':
                pattern = "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:00:00(\\.0+)?Z$"
            elif instance[prop_name] == 'minute':
                pattern = "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:00(\\.0+)?Z$"

            if not re.match(pattern, instance[ts_field]):
                yield JSONError("%s timestamp is not the correct format for '%s' "
                                "precision." % (ts_field, instance[prop_name]),
                                instance['id'])


def object_marking_circular_refs(instance):
    """Ensure that marking definitions do not contain circular references (ie.
    they do not reference themselves in the `object_marking_refs` property).
    """
    if instance['type'] != 'marking-definition':
        return

    if 'object_marking_refs' in instance:
        for ref in instance['object_marking_refs']:
            if ref == instance['id']:
                yield JSONError("`object_marking_refs` cannot contain any "
                                "references to this marking definition object"
                                " (no circular references).", instance['id'])


def granular_markings_circular_refs(instance):
    """Ensure that marking definitions do not contain circular references (ie.
    they do not reference themselves in the `granular_markings` property).
    """
    if instance['type'] != 'marking-definition':
        return

    if 'granular_markings' in instance:
        for marking in instance['granular_markings']:
            if 'marking_ref' in marking and marking['marking_ref'] == instance['id']:
                yield JSONError("`granular_markings` cannot contain any "
                                "references to this marking definition object"
                                " (no circular references).", instance['id'])


def marking_selector_syntax(instance):
    """Ensure selectors in granular markings refer to items which are actually
    present in the object.
    """
    if 'granular_markings' not in instance:
        return

    for marking in instance['granular_markings']:
        if 'selectors' not in marking:
            continue

        selectors = marking['selectors']
        for selector in selectors:
            segments = selector.split('.')

            obj = instance
            prev_segmt = None
            for segmt in segments:
                index_match = re.match(r"\[(\d+)\]", segmt)
                if index_match:
                    try:
                        idx = int(index_match.group(1))
                        obj = obj[idx]
                    except IndexError as e:
                        yield JSONError("'%s' is not a valid selector because"
                                        " %s is not a valid index."
                                        % (selector, idx), instance['id'])
                    except KeyError as e:
                        yield JSONError("'%s' is not a valid selector because"
                                        " '%s' is not a list."
                                        % (selector, prev_segmt), instance['id'])
                else:
                    try:
                        obj = obj[segmt]
                    except KeyError as e:
                        yield JSONError("'%s' is not a valid selector because"
                                        " %s is not a property."
                                        % (selector, e), instance['id'])
                    except TypeError as e:
                        yield JSONError("'%s' is not a valid selector because"
                                        " '%s' is not a property."
                                        % (selector, segmt), instance['id'])
                prev_segmt = segmt


# Checks for SHOULD Requirements

def custom_object_prefix_strict(instance):
    """Ensure custom objects follow strict naming style conventions.
    """
    if (instance['type'] not in enums.TYPES and
            instance['type'] not in enums.RESERVED_OBJECTS and
            not re.match("^x\-.+\-.+$", instance['type'])):
        yield JSONError("Custom object type '%s' should start with 'x-' "
                        "followed by a source unique identifier (like a"
                        "domain name with dots replaced by dashes), a dash "
                        "and then the name." % instance['type'],
                        instance['id'], 'custom-object-prefix')


def custom_object_prefix_lax(instance):
    """Ensure custom objects follow lenient naming style conventions
    for forward-compatibility.
    """
    if (instance['type'] not in enums.TYPES and
            instance['type'] not in enums.RESERVED_OBJECTS and
            not re.match("^x\-.+$", instance['type'])):
        yield JSONError("Custom object type '%s' should start with 'x-' in "
                        "order to be compatible with future versions of the "
                        "STIX 2 specification." % instance['type'],
                        instance['id'], 'custom-object-prefix')


def custom_property_prefix_strict(instance):
    """Ensure custom properties follow strict naming style conventions.

    Does not check property names in custom objects.
    """
    for prop_name in instance.keys():
        if (instance['type'] in enums.PROPERTIES and
                prop_name not in enums.PROPERTIES[instance['type']] and
                prop_name not in enums.RESERVED_PROPERTIES and
                not re.match("^x_.+_.+$", prop_name)):

            yield JSONError("Custom property '%s' should have a type that "
                            "starts with 'x_' followed by a source unique "
                            "identifier (like a domain name with dots "
                            "replaced by dashes), a dash and then the name." %
                            prop_name, instance['id'],
                            'custom-property-prefix')


def custom_property_prefix_lax(instance):
    """Ensure custom properties follow lenient naming style conventions
    for forward-compatibility.

    Does not check property names in custom objects.
    """
    for prop_name in instance.keys():
        if (instance['type'] in enums.PROPERTIES and
                prop_name not in enums.PROPERTIES[instance['type']] and
                prop_name not in enums.RESERVED_PROPERTIES and
                not re.match("^x_.+$", prop_name)):

            yield JSONError("Custom property '%s' should have a type that "
                            "starts with 'x_' in order to be compatible with "
                            "future versions of the STIX 2 specification." %
                            prop_name, instance['id'],
                            'custom-property-prefix')


def open_vocab_values(instance):
    """Ensure that the values of all properties which use open vocabularies are
    in lowercase and use dashes instead of spaces or underscores as word
    separators.
    """
    if instance['type'] not in enums.VOCAB_PROPERTIES:
        return

    properties = enums.VOCAB_PROPERTIES[instance['type']]
    for prop in properties:
        if prop in instance:

            if type(instance[prop]) is list:
                values = instance[prop]
            else:
                values = [instance[prop]]

            for v in values:
                if not v.islower() or '_' in v or ' ' in v:
                    yield JSONError("Open vocabulary value '%s' should be all"
                                    " lowercase and use dashes instead of"
                                    " spaces or underscores as word"
                                    " separators." % v, instance['id'],
                                    'open-vocab-format')


def kill_chain_phase_names(instance):
    """Ensure the `kill_chain_name` and `phase_name` properties of
    `kill_chain_phase` objects follow naming style conventions.
    """
    if instance['type'] in enums.KILL_CHAIN_PHASE_USES and 'kill_chain_phases' in instance:
        for phase in instance['kill_chain_phases']:

            if 'kill_chain_name' not in phase:
                # Since this field is required, schemas will already catch the error
                return

            chain_name = phase['kill_chain_name']
            if not chain_name.islower() or '_' in chain_name or ' ' in chain_name:
                yield JSONError("kill_chain_name '%s' should be all lowercase"
                                " and use dashes instead of spaces or "
                                "underscores as word separators." % chain_name,
                                instance['id'], 'kill-chain-names')

            phase_name = phase['phase_name']
            if not phase_name.islower() or '_' in phase_name or ' ' in phase_name:
                yield JSONError("phase_name '%s' should be all lowercase and "
                                "use dashes instead of spaces or underscores "
                                "as word separators." % phase_name,
                                instance['id'], 'kill-chain-names')


def check_vocab(instance, vocab, code):
    """Ensure that the open vocabulary specified by `vocab` is used properly.

    This checks properties of objects specified in the appropriate `_USES`
    dictionary to determine which properties SHOULD use the given vocabulary,
    then checks that the values in those properties are from the vocabulary.
    """
    vocab_uses = getattr(enums, vocab + "_USES")
    for k in vocab_uses.keys():
        if instance['type'] == k:
            for prop in vocab_uses[k]:
                if prop not in instance:
                    continue

                vocab_ov = getattr(enums, vocab + "_OV")
                if type(instance[prop]) is list:
                    is_in = set(instance[prop]).issubset(set(vocab_ov))
                else:
                    is_in = instance[prop] in vocab_ov

                if not is_in:
                    vocab_name = vocab.replace('_', '-').lower()
                    yield JSONError("%s contains a value not in the %s-ov "
                                    "vocabulary." % (prop, vocab_name),
                                    instance['id'], code)


def vocab_attack_motivation(instance):
    return check_vocab(instance, "ATTACK_MOTIVATION",
                       'attack-motivation')


def vocab_attack_resource_level(instance):
    return check_vocab(instance, "ATTACK_RESOURCE_LEVEL",
                       'attack-resource-level')


def vocab_identity_class(instance):
    return check_vocab(instance, "IDENTITY_CLASS",
                       'identity-class')


def vocab_indicator_label(instance):
    return check_vocab(instance, "INDICATOR_LABEL",
                       'indicator-label')


def vocab_industry_sector(instance):
    return check_vocab(instance, "INDUSTRY_SECTOR",
                       'indicator-label')


def vocab_malware_label(instance):
    return check_vocab(instance, "MALWARE_LABEL",
                       'malware-label')


def vocab_report_label(instance):
    return check_vocab(instance, "REPORT_LABEL",
                       'report-label')


def vocab_threat_actor_label(instance):
    return check_vocab(instance, "THREAT_ACTOR_LABEL",
                       'threat-actor-label')


def vocab_threat_actor_role(instance):
    return check_vocab(instance, "THREAT_ACTOR_ROLE",
                       'threat-actor-role')


def vocab_threat_actor_sophistication_level(instance):
    return check_vocab(instance, "THREAT_ACTOR_SOPHISTICATION",
                       'threat-actor-sophistication')


def vocab_tool_label(instance):
    return check_vocab(instance, "TOOL_LABEL",
                       'tool-label')


def vocab_marking_definition(instance):
    """Ensure that the `definition_type` property of `marking-definition`
    objects is one of the values in the STIX 2.0 specification.
    """
    if (instance['type'] == 'marking-definition' and
            'definition_type' in instance and not
            instance['definition_type'] in enums.MARKING_DEFINITION_TYPES):

        return JSONError("Marking definition `definition_type` should be one "
                         "of: %s." % ', '.join(enums.MARKING_DEFINITION_TYPES),
                         instance['id'], 'marking-definition-type')


def relationships_strict(instance):
    """Ensure that only the relationship types defined in the specification are
    used.
    """
    # Don't check objects that aren't relationships or that are custom objects
    if (instance['type'] != 'relationship' or
            instance['type'] not in enums.TYPES):
        return

    if ('relationship_type' not in instance or 'source_ref' not in instance or
            'target_ref' not in instance):
        # Since these fields are required, schemas will already catch the error
        return

    r_type = instance['relationship_type']
    r_source = re.search("(.+)\-\-", instance['source_ref']).group(1)
    r_target = re.search("(.+)\-\-", instance['target_ref']).group(1)

    if (r_type in enums.COMMON_RELATIONSHIPS or
            r_source in enums.DENIED_RELATIONSHIPS or
            r_target in enums.DENIED_RELATIONSHIPS):
        # Schemas will already catch relationships not allowed by spec
        return

    if r_source not in enums.RELATIONSHIPS:
        return JSONError("'%s' is not a suggested relationship source object "
                         "for the '%s' relationship." % (r_source, r_type),
                         instance['id'], 'relationship-types')

    if r_type not in enums.RELATIONSHIPS[r_source]:
        return JSONError("'%s' is not a suggested relationship type for '%s' "
                         "objects." % (r_type, r_source), instance['id'],
                         'relationship-types')

    if r_target not in enums.RELATIONSHIPS[r_source][r_type]:
        return JSONError("'%s' is not a suggested relationship target object "
                         "for '%s' objects with the '%s' relationship."
                         % (r_target, r_source, r_type), instance['id'],
                         'relationship-types')


def has_cyber_observable_data(instance):
    """Return True only if the given instance is an observed-data object
    containing STIX Cyber Observable objects.
    """
    if (instance['type'] == 'observed-data' and
            'objects' in instance and
            type(instance['objects']) is dict):
        return True
    return False


def test_dict_keys(item, inst_id):
    """Recursively generate errors for incorrectly formatted cyber observable
    dictionary keys.
    """
    for k, v in item.items():
        # Skip hashes_type objects
        if k == 'hashes' or k == 'file_header_hashes':
            continue

        if not re.match("^[^A-Z]+$", k):
            yield JSONError("As a dictionary key for cyber observable "
                            "objects, '%s' should be lowercase." % k,
                            inst_id)
        if not len(k) <= 30:
            yield JSONError("As a dictionary key for cyber observable "
                            "objects, '%s' should be no longer than 30 "
                            "characters long." % k, inst_id)

        if type(v) is dict:
            for error in test_dict_keys(v, inst_id):
                yield error


def observable_dictionary_keys(instance):
    """Ensure dictionaries in the cyber observable layer have lowercase keys
    no longer than 30 characters.
    """
    if not has_cyber_observable_data(instance):
        return

    for error in test_dict_keys(instance['objects'], instance['id']):
        yield error


def valid_hash_value(hashname):
    """Return true if given value is a valid, recommended hash name according
    to the STIX 2 specification.
    """
    if hashname in enums.HASH_ALGO_OV or re.match("^x_", hashname):
        return True
    else:
        return False


def vocab_hash_algo(instance):
    """Ensure objects with 'hashes' properties only use values from the
    hash-algo-ov vocabulary.
    """
    if not has_cyber_observable_data(instance):
        return

    for key, obj in instance['objects'].items():
        if 'type' not in obj:
            continue

        if obj['type'] == 'file':
            try:
                hashes = obj['hashes']
            except KeyError:
                pass
            else:
                for h in hashes:
                    if not (valid_hash_value(h)):
                        yield JSONError("Object '%s' has a 'hashes' dictionary"
                                " with a hash of type '%s', which is not a "
                                "value in the hash-algo-ov vocabulary nor a "
                                "custom value prepended with 'x_'."
                                % (key, h), instance['id'])

            try:
                ads = obj['extensions']['ntfs-ext']['alternate_data_streams']
            except KeyError:
                pass
            else:
                for datastream in ads:
                    if 'hashes' not in datastream:
                        continue
                    for h in datastream['hashes']:
                        if not (valid_hash_value(h)):
                            yield JSONError("Object '%s' has an NTFS extension"
                                    " with an alternate data stream that has a"
                                    " 'hashes' dictionary with a hash of type "
                                    "'%s', which is not a value in the "
                                    "hash-algo-ov vocabulary nor a custom "
                                    "value prepended with 'x_'."
                                    % (key, h), instance['id'])

            try:
                head_hashes = obj['extensions']['windows-pebinary-ext']['file_header_hashes']
            except KeyError:
                pass
            else:
                for h in head_hashes:
                    if not (valid_hash_value(h)):
                        yield JSONError("Object '%s' has a Windows PE Binary "
                                "File extension with a file header hash of "
                                "'%s', which is not a value in the "
                                "hash-algo-ov vocabulary nor a custom value "
                                "prepended with 'x_'."
                                % (key, h), instance['id'])

            try:
                hashes = obj['extensions']['windows-pebinary-ext']['optional_header']['hashes']
            except KeyError:
                pass
            else:
                for h in hashes:
                    if not (valid_hash_value(h)):
                        yield JSONError("Object '%s' has a Windows PE Binary "
                                "File extension with an optional header that "
                                "has a hash of '%s', which is not a value in "
                                "the hash-algo-ov vocabulary nor a custom "
                                "value prepended with 'x_'."
                                % (key, h), instance['id'])

            try:
                sections = obj['extensions']['windows-pebinary-ext']['sections']
            except KeyError:
                pass
            else:
                for s in sections:
                    if 'hashes' not in s:
                        continue
                    for h in s['hashes']:
                        if not (valid_hash_value(h)):
                            yield JSONError("Object '%s' has a Windows PE "
                                    "Binary File extension with a section that"
                                    " has a hash of '%s', which is not a value"
                                    " in the hash-algo-ov vocabulary nor a "
                                    "custom value prepended with 'x_'."
                                    % (key, h), instance['id'])

        elif obj['type'] == 'artifact' or obj['type'] == 'x509-certificate':
            try:
                hashes = obj['hashes']
            except KeyError:
                pass
            else:
                for h in hashes:
                    if not (valid_hash_value(h)):
                        yield JSONError("Object '%s' has a 'hashes' dictionary"
                                " with a hash of type '%s', which is not a "
                                "value in the hash-algo-ov vocabulary nor a "
                                "custom value prepended with 'x_'."
                                % (key, h), instance['id'])


def vocab_encryption_algo(instance):
    """Ensure file objects' 'encryption_algorithm' property is from the
    encryption-algo-ov vocabulary.
    """
    if not has_cyber_observable_data(instance):
        return

    for key, obj in instance['objects'].items():
        if 'type' in obj and obj['type'] == 'file':
            try:
                enc_algo = obj['encryption_algorithm']
            except KeyError:
                continue
            if enc_algo not in enums.ENCRYPTION_ALGO_OV:
                yield JSONError("Object '%s' has an 'encryption_algorithm' of "
                                "'%s', which is not a value in the "
                                "encryption-algo-ov vocabulary."
                                % (key, enc_algo), instance['id'])


def vocab_windows_pebinary_type(instance):
    """Ensure file objects with the windows-pebinary-ext extension have a 
    'pe-type' property that is from the account-type-ov vocabulary.
    """
    if not has_cyber_observable_data(instance):
        return

    for key, obj in instance['objects'].items():
        if 'type' in obj and obj['type'] == 'file':
            try:
                pe_type = obj['extensions']['windows-pebinary-ext']['pe_type']
            except KeyError:
                continue
            if pe_type not in enums.WINDOWS_PEBINARY_TYPE_OV:
                yield JSONError("Object '%s' has a Windows PE Binary File "
                        "extension with a 'pe_type' of '%s', which is not a "
                        "value in the windows-pebinary-type-ov vocabulary."
                        % (key, pe_type), instance['id'])


def vocab_account_type(instance):
    """Ensure a user-account objects' 'account-type' property is from the
    account-type-ov vocabulary.
    """
    if not has_cyber_observable_data(instance):
        return

    for key, obj in instance['objects'].items():
        if 'type' in obj and obj['type'] == 'user-account':
            try:
                acct_type = obj['account_type']
            except KeyError:
                continue
            if acct_type not in enums.ACCOUNT_TYPE_OV:
                yield JSONError("Object '%s' is a User Account Object "
                        "with an 'account_type' of '%s', which is not a "
                        "value in the account-type-ov vocabulary."
                        % (key, acct_type), instance['id'])


def types_strict(instance):
    """Ensure that no custom object types are used, but only the official ones
    from the specification.
    """
    if instance['type'] not in enums.TYPES:
        return JSONError("Object type '%s' is not one of those detailed in the"
                         " specification." % instance['type'], instance['id'])


# Mapping of check code numbers to names
CHECK_CODES = {
    '1': 'format-checks',
    '101': 'custom-object-prefix',
    '102': 'custom-object-prefix-lax',
    '103': 'custom-property-prefix',
    '104': 'custom-property-prefix-lax',
    '111': 'open-vocab-format',
    '121': 'kill-chain-names',
    '2': 'approved-values',
    '210': 'all-vocabs',
    '211': 'attack-motivation',
    '212': 'attack-resource-level',
    '213': 'identity-class',
    '214': 'indicator-label',
    '215': 'industry-sector',
    '216': 'malware-label',
    '218': 'report-label',
    '219': 'threat-actor-label',
    '220': 'threat-actor-role',
    '221': 'threat-actor-sophistication',
    '222': 'tool-label',
    '229': 'marking-definition-type',
    '250': 'relationship-types'
}

# Mapping of check names to the functions which perform the checks
CHECKS = {
    'all': [
        custom_object_prefix_strict,
        custom_property_prefix_strict,
        open_vocab_values,
        kill_chain_phase_names,
        vocab_attack_motivation,
        vocab_attack_resource_level,
        vocab_identity_class,
        vocab_indicator_label,
        vocab_industry_sector,
        vocab_malware_label,
        vocab_report_label,
        vocab_threat_actor_label,
        vocab_threat_actor_role,
        vocab_threat_actor_sophistication_level,
        vocab_tool_label,
        vocab_marking_definition,
        relationships_strict
    ],
    'format-checks': [
        custom_object_prefix_strict,
        custom_property_prefix_strict,
        open_vocab_values,
        kill_chain_phase_names
    ],
    'custom-object-prefix': custom_object_prefix_strict,
    'custom-object-prefix-lax': custom_object_prefix_lax,
    'custom-property-prefix': custom_property_prefix_strict,
    'custom-property-prefix-lax': custom_property_prefix_lax,
    'open-vocab-format': open_vocab_values,
    'kill-chain-names': kill_chain_phase_names,
    'approved-values': [
        vocab_attack_motivation,
        vocab_attack_resource_level,
        vocab_identity_class,
        vocab_indicator_label,
        vocab_industry_sector,
        vocab_malware_label,
        vocab_report_label,
        vocab_threat_actor_label,
        vocab_threat_actor_role,
        vocab_threat_actor_sophistication_level,
        vocab_tool_label,
        vocab_marking_definition,
        relationships_strict
    ],
    'all-vocabs': [
        vocab_attack_motivation,
        vocab_attack_resource_level,
        vocab_identity_class,
        vocab_indicator_label,
        vocab_industry_sector,
        vocab_malware_label,
        vocab_report_label,
        vocab_threat_actor_label,
        vocab_threat_actor_role,
        vocab_threat_actor_sophistication_level,
        vocab_tool_label,
        vocab_marking_definition
    ],
    'attack-motivation': vocab_attack_motivation,
    'attack-resource-level': vocab_attack_resource_level,
    'identity-class': vocab_identity_class,
    'indicator-label': vocab_indicator_label,
    'industry-sector': vocab_industry_sector,
    'malware-label': vocab_malware_label,
    'report-label': vocab_report_label,
    'threat-actor-label': vocab_threat_actor_label,
    'threat-actor-role': vocab_threat_actor_role,
    'threat-actor-sophistication': vocab_threat_actor_sophistication_level,
    'tool-label': vocab_tool_label,
    'marking-definition-type': vocab_marking_definition,
    'relationship-types': relationships_strict
}


class CustomDraft4Validator(Draft4Validator):
    """Custom validator class for JSON Schema Draft 4.

    """
    def __init__(self, schema, types=(), resolver=None, format_checker=None,
                 options=ValidationOptions()):
        super(CustomDraft4Validator, self).__init__(schema, types, resolver,
                                                    format_checker)
        self.validator_list = self.list_validators(options)
        self.shoulds_list = self.list_shoulds(options)

    def list_validators(self, options):
        """Construct the list of validators to be run by this validator.
        """
        validator_list = [
            modified_created,
            version,
            timestamp_precision,
            object_marking_circular_refs,
            granular_markings_circular_refs,
            marking_selector_syntax
        ]

        # --strict-types
        if options.strict_types:
            validator_list.append(types_strict)

        return validator_list

    def list_shoulds(self, options):
        validator_list = []

        # TODO: make these optional, and add check codes to all of them
        validator_list.extend([
            observable_dictionary_keys,
            vocab_hash_algo,
            vocab_encryption_algo,
            vocab_windows_pebinary_type,
            vocab_account_type
        ])

        # Default: enable all
        if not options.disabled and not options.enabled:
            validator_list.extend(CHECKS['all'])
            return validator_list

        # --disable
        # Add SHOULD requirements to the list unless disabled
        if options.disabled:
            if 'all' not in options.disabled:
                if 'format-checks' not in options.disabled:
                    if ('custom-object-prefix' not in options.disabled and
                            'custom-object-prefix-lax' not in options.disabled):
                        validator_list.append(CHECKS['custom-object-prefix'])
                    elif 'custom-object-prefix' not in options.disabled:
                        validator_list.append(CHECKS['custom-object-prefix'])
                    elif 'custom-object-prefix-lax' not in options.disabled:
                        validator_list.append(CHECKS['custom-object-prefix-lax'])
                    if ('custom-property-prefix' not in options.disabled and
                            'custom-property-prefix-lax' not in options.disabled):
                        validator_list.append(CHECKS['custom-property-prefix'])
                    elif 'custom-property-prefix' not in options.disabled:
                        validator_list.append(CHECKS['custom-property-prefix'])
                    elif 'custom-property-prefix-lax' not in options.disabled:
                        validator_list.append(CHECKS['custom-property-prefix-lax'])
                    if 'open-vocab-format' not in options.disabled:
                        validator_list.append(CHECKS['open-vocab-format'])
                    if 'kill-chain-names' not in options.disabled:
                        validator_list.append(CHECKS['kill-chain-names'])

                if 'approved-values' not in options.disabled:
                    if 'all-vocabs' not in options.disabled:
                        if 'attack-motivation' not in options.disabled:
                            validator_list.append(CHECKS['attack-motivation'])
                        if 'attack-resource-level' not in options.disabled:
                            validator_list.append(CHECKS['attack-resource-level'])
                        if 'identity-class' not in options.disabled:
                            validator_list.append(CHECKS['identity-class'])
                        if 'indicator-label' not in options.disabled:
                            validator_list.append(CHECKS['indicator-label'])
                        if 'industry-sector' not in options.disabled:
                            validator_list.append(CHECKS['industry-sector'])
                        if 'malware-label' not in options.disabled:
                            validator_list.append(CHECKS['malware-label'])
                        if 'report-label' not in options.disabled:
                            validator_list.append(CHECKS['report-label'])
                        if 'threat-actor-label' not in options.disabled:
                            validator_list.append(CHECKS['threat-actor-label'])
                        if 'threat-actor-role' not in options.disabled:
                            validator_list.append(CHECKS['threat-actor-role'])
                        if 'threat-actor-sophistication' not in options.disabled:
                            validator_list.append(CHECKS['threat-actor-sophistication'])
                        if 'tool-label' not in options.disabled:
                            validator_list.append(CHECKS['tool-label'])
                        if 'marking-definition-type' not in options.disabled:
                            validator_list.append(CHECKS['marking-definition-type'])
                    if 'relationship-types' not in options.disabled:
                        validator_list.append(CHECKS['relationship-types'])

        # --enable
        if options.enabled:
            for check in options.enabled:
                try:
                    if CHECKS[check] in validator_list:
                        continue

                    if type(CHECKS[check]) is list:
                        validator_list.extend(CHECKS[check])
                    else:
                        validator_list.append(CHECKS[check])
                except KeyError:
                    raise schema_exceptions.ValidationError("%s is not a valid"
                                                            " check!" % check)

        return validator_list

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
            validators = self.validator_list
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
