"""Custom jsonschema.IValidator class and validator functions.
"""

# builtin
import re
from collections import deque

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
        lax: Specifies that only mandatory requirements, not ones which are
            merely recommended, should be checked.
        lax_prefix: Specifies that less strict requirements for custom object
            and property names should be used.
        strict_types: Specifies that no custom object types be used, only
            those detailed in the STIX specification.

    """
    def __init__(self, cmd_args=None, verbose=False, files=None,
                 recursive=False, schema_dir="schemas/", ignored="",
                 enabled="", lax=False, strict_types=False):
        if cmd_args is not None:
            self.verbose = cmd_args.verbose
            self.files = cmd_args.files
            self.recursive = cmd_args.recursive
            self.schema_dir = cmd_args.schema_dir
            self.ignored = cmd_args.ignored
            self.enabled = cmd_args.enabled
            self.lax = cmd_args.lax
            self.strict_types = cmd_args.strict_types
        else:
            # input options
            self.files = files
            self.recursive = recursive
            self.schema_dir = schema_dir

            # output options
            self.verbose = verbose
            self.lax = lax
            self.strict_types = strict_types
            self.ignored = ignored
            self.enabled = enabled

        # Convert string of comma-separated checks to a list,
        # and convert check code numbers to names
        if self.ignored:
            self.ignored = self.ignored.split(",")
            self.ignored = [CHECK_CODES[x] if x in CHECK_CODES else x
                                   for x in self.ignored]
        if self.enabled:
            self.enabled = self.enabled.split(",")
            self.enabled = [CHECK_CODES[x] if x in CHECK_CODES else x
                                   for x in self.enabled]


class JSONError(schema_exceptions.ValidationError):
    """Wrapper for errors thrown by iter_errors() in the jsonschema module.
    """
    def __init__(self, msg=None, instance_type=None, check_code=None):
        if check_code is not None:
            # Get code number code from name
            code = list(CHECK_CODES.keys())[list(CHECK_CODES.values()).index(check_code)]
            msg = '{%s} %s' % (code, msg)
        super(JSONError, self).__init__(msg, path=deque([instance_type]))


# Checks for MUST Requirements

def modified_created(instance):
    """`modified` property must be later or equal to `created` property
    """
    if 'modified' in instance and 'created' in instance and \
            instance['modified'] < instance['created']:
        return JSONError("'modified' (%s) must be later or equal to 'created' (%s)"
            % (instance['modified'], instance['created']), instance['type'])


def version(instance):
    """Check constraints on 'version' property
    """
    if 'version' in instance and 'modified' in instance and \
            'created' in instance:
        if instance['version'] == 1 and instance['modified'] != instance['created']:
            return JSONError("'version' is 1, but 'created' (%s) is not "
                "equal to 'modified' (%s)" 
                % (instance['created'], instance['modified']), instance['type'])
        elif instance['version'] > 1 and instance['modified'] <= instance['created']:
            return JSONError("'version' is greater than 1, but 'modified'"
                " (%s) is not greater than 'created' (%s)" 
                % (instance['modified'], instance['created']), instance['type'])


def id_type(instance):
    """Ensure that an object's id` starts with its type.
    Checking of the UUID portion of the id is handled in the JSON schemas.
    """
    t = instance['type']
    if not re.search("%s\-\-" % t, instance['id']):
        return JSONError("'id' must be prefixed by %s--." % t, t)


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
            return JSONError("There is no corresponding %s field" % ts_field, prop_name)

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
            return JSONError("Timestamp is not the correct format for '%s' "
                             "precision." % instance[prop_name], ts_field)


# Checks for SHOULD Requirements

def custom_object_prefix_strict(instance):
    """Ensure custom objects follow strict naming style conventions.
    """
    if instance['type'] not in enums.TYPES and not re.match("^x\-.+\-.+$", instance['type']):
        return JSONError("Custom objects should have a type that starts with "
                         "'x-' followed by a source unique identifier (like "
                         "a domain name with dots replaced by dashes), a dash "
                         "and then the name.", instance['type'],
                         'custom-object-prefix')


def custom_object_prefix_lax(instance):
    """Ensure custom objects follow lenient naming style conventions
    for forward-compatibility.
    """
    if instance['type'] not in enums.TYPES and not re.match("^x\-.+$", instance['type']):
        return JSONError("Custom objects should have a type that starts with "
                         "'x-' in order to be compatible with future versions"
                         " of the STIX 2 specification.", instance['type'],
                         'custom-object-prefix')


def custom_property_prefix_strict(instance):
    """Ensure custom properties follow strict naming style conventions.

    Does not check property names in custom objects.
    """
    for prop_name in instance.keys():
        if (instance['type'] in enums.PROPERTIES and
                prop_name not in enums.PROPERTIES[instance['type']] and
                not re.match("^x_.+_.+$", prop_name)):

            return JSONError("Custom properties should have a type that starts"
                             " with 'x_' followed by a source unique "
                             "identifier (like a domain name with dots "
                             "replaced by dashes), a dash and then the name.",
                             prop_name, 'custom-property-prefix')


def custom_property_prefix_lax(instance):
    """Ensure custom properties follow lenient naming style conventions
    for forward-compatibility.

    Does not check property names in custom objects.
    """
    for prop_name in instance.keys():
        if (instance['type'] in enums.PROPERTIES and
                prop_name not in enums.PROPERTIES[instance['type']] and
                not re.match("^x_.+$", prop_name)):

            return JSONError("Custom properties should have a type that starts"
                             " with 'x_' in order to be compatible with future"
                             " versions of the STIX 2 specification.",
                             prop_name, 'custom-property-prefix')


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
                    return JSONError("Open vocabulary value (%s) should be all"
                                     " lowercase and use dashes instead of"
                                     " spaces or underscores as word"
                                     " separators." % v, instance['type'],
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
                return JSONError("kill_chain_name (%s) should be all lowercase"
                                 " and use dashes instead of spaces or "
                                 "underscores as word separators." % chain_name,
                                 instance['type'], 'kill-chain-names')

            phase_name = phase['phase_name']
            if not phase_name.islower() or '_' in phase_name or ' ' in phase_name:
                return JSONError("phase_name (%s) should be all lowercase and "
                                 "use dashes instead of spaces or underscores "
                                 "as word separators." % phase_name,
                                 instance['type'], 'kill-chain-names')


def check_vocab(instance, vocab, code):
    """Ensure that the open vocabulary specified by `vocab` is used properly.

    It checks properties of objects specified in the appropriate `_USES`
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
                    return JSONError("%s contains a value not in the %s-ov "
                                     "vocabulary." % (prop, vocab_name), prop,
                                     code)


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


def vocab_pattern_lang(instance):
    return check_vocab(instance, "PATTERN_LANG",
                       'pattern-lang')


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

        return JSONError("Marking definition's `definition_type` should be one"
                         " of %s." % enums.MARKING_DEFINITION_TYPES,
                         instance['type'], 'marking-definition-type')


def relationships_strict(instance):
    """Ensure that only the relationship types defined in the specification are
    used.
    """
    # Don't check objects that aren't relationships or are custom objects
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

    if r_source not in enums.RELATIONSHIPS:
        return JSONError("'%s' is not a valid relationship source object."
                         % r_source, "relationship_type",
                         'relationship-types')

    if r_type not in enums.RELATIONSHIPS[r_source]:
        return JSONError("'%s' is not a valid relationship type for '%s' "
                         "objects." % (r_type, r_source), "relationship_type",
                         'relationship-types')

    if r_target not in enums.RELATIONSHIPS[r_source][r_type]:
        return JSONError("'%s' is not a valid relationship target object for "
                         "'%s' objects with the '%s' relationship."
                         % (r_target, r_source, r_type), "relationship_type",
                         'relationship-types')


def types_strict(instance):
    """Ensure that no custom object types are used, but only the official ones
    from the specification.
    """
    if instance['type'] not in enums.TYPES:
        return JSONError("Object type should be one of those detailed in the"
                         " specification.", instance['type'])


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
    '217': 'pattern-lang',
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
        custom_object_prefix_lax,
        custom_property_prefix_strict,
        custom_property_prefix_lax,
        open_vocab_values,
        kill_chain_phase_names,
        vocab_attack_motivation,
        vocab_attack_resource_level,
        vocab_identity_class,
        vocab_indicator_label,
        vocab_industry_sector,
        vocab_malware_label,
        vocab_pattern_lang,
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
        custom_object_prefix_lax,
        custom_property_prefix_strict,
        custom_property_prefix_lax,
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
        vocab_pattern_lang,
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
        vocab_pattern_lang,
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
    'pattern-lang': vocab_pattern_lang,
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

    def list_validators(self, options):
        """Construct the list of validators to be run by this validator.
        """
        validator_list = [
            modified_created,
            version,
            id_type,
            timestamp_precision
        ]

        # --strict-types
        if options.strict_types:
            validator_list.append(types_strict)

        # --lax
        # If only checking MUST requirements, the list is complete
        if options.lax:
            return validator_list

        # Default: enable all
        if not options.ignored and not options.enabled:
            validator_list.extend(CHECKS['format-checks'])
            validator_list.extend(CHECKS['approved-values'])
            return validator_list

        # --disable
        # Add SHOULD requirements to the list unless ignored
        if options.ignored:
            if 'all' not in options.ignored:
                if 'format-checks' not in options.ignored:
                    if ('custom-object-prefix' not in options.ignored and
                            'custom-object-prefix-lax' not in options.ignored):
                        validator_list.append(CHECKS['custom-object-prefix'])
                    elif 'custom-object-prefix' not in options.ignored:
                        validator_list.append(CHECKS['custom-object-prefix'])
                    elif 'custom-object-prefix-lax' not in options.ignored:
                        validator_list.append(CHECKS['custom-object-prefix-lax'])
                    if ('custom-property-prefix' not in options.ignored and
                            'custom-property-prefix-lax' not in options.ignored):
                        validator_list.append(CHECKS['custom-property-prefix'])
                    elif 'custom-property-prefix' not in options.ignored:
                        validator_list.append(CHECKS['custom-property-prefix'])
                    elif 'custom-property-prefix-lax' not in options.ignored:
                        validator_list.append(CHECKS['custom-property-prefix-lax'])
                    if 'open-vocab-format' not in options.ignored:
                        validator_list.append(CHECKS['open-vocab-format'])
                    if 'kill-chain-names' not in options.ignored:
                        validator_list.append(CHECKS['kill-chain-names'])

                if 'approved-values' not in options.ignored:
                    if 'all-vocabs' not in options.ignored:
                        if 'attack-motivation' not in options.ignored:
                            validator_list.append(CHECKS['attack-motivation'])
                        if 'attack-resource-level' not in options.ignored:
                            validator_list.append(CHECKS['attack-resource-level'])
                        if 'identity-class' not in options.ignored:
                            validator_list.append(CHECKS['identity-class'])
                        if 'indicator-label' not in options.ignored:
                            validator_list.append(CHECKS['indicator-label'])
                        if 'industry-sector' not in options.ignored:
                            validator_list.append(CHECKS['industry-sector'])
                        if 'malware-label' not in options.ignored:
                            validator_list.append(CHECKS['malware-label'])
                        if 'pattern-lang' not in options.ignored:
                            validator_list.append(CHECKS['pattern-lang'])
                        if 'report-label' not in options.ignored:
                            validator_list.append(CHECKS['report-label'])
                        if 'threat-actor-label' not in options.ignored:
                            validator_list.append(CHECKS['threat-actor-label'])
                        if 'threat-actor-role' not in options.ignored:
                            validator_list.append(CHECKS['threat-actor-role'])
                        if 'threat-actor-sophistication' not in options.ignored:
                            validator_list.append(CHECKS['threat-actor-sophistication'])
                        if 'tool-label' not in options.ignored:
                            validator_list.append(CHECKS['tool-label'])
                        if 'marking-definition-type' not in options.ignored:
                            validator_list.append(CHECKS['marking-definition-type'])
                    if 'relationship-types' not in options.ignored:
                        validator_list.append(CHECKS['relationship-types'])

        # --enable
        if options.enabled:
            for check in options.enabled:
                if CHECKS[check] in validator_list:
                    continue

                try:
                    if type(CHECKS[check]) is list:
                        validator_list.extend(CHECKS[check])
                    else:
                        validator_list.append(CHECKS[check])
                except KeyError:
                    raise schema_exceptions.ValidationError("%s is not a valid"
                                                            " check!" % check)

        return validator_list

    def iter_errors_more(self, instance, options=None, _schema=None):
        """Perform additional validation not possible merely with JSON schemas.

        """
        # Ensure `instance` is a whole STIX object, not just a property of one
        if not (type(instance) is dict and 'id' in instance and 'type' in instance):
            return

        if _schema is None:
            _schema = self.schema

        # Perform validation
        for v_function in self.validator_list:
            result = v_function(instance)
            if result is not None:
                yield result

        # Validate any child STIX objects
        for field in instance:
            if type(instance[field]) is list:
                for obj in instance[field]:
                    for err in self.iter_errors_more(obj, _schema):
                        yield err
