"""Recommended (SHOULD) requirement checking functions

To add a new check:
- in this module:
    - define a new function
    - add the function to CHECKS
    - add the function to list_shoulds()
- in enums.py:
    - add the check code and name to CHECK_CODES
- in util.py:
    - add the check code and name to table
- in docs/best-practices:
    - add the check code and name to table
"""

from collections.abc import Iterable, Mapping
from itertools import chain
import re

from six import string_types
from stix2patterns.v20.pattern import Pattern

from . import enums
from ..errors import PatternError
from ..output import info
from ..util import cyber_observable_check, has_cyber_observable_data
from .errors import JSONError
from .musts import (CUSTOM_PROPERTY_LAX_PREFIX_RE, CUSTOM_PROPERTY_PREFIX_RE,
                    CUSTOM_TYPE_LAX_PREFIX_RE, CUSTOM_TYPE_PREFIX_RE)

PROTOCOL_RE = re.compile(r'^[a-zA-Z0-9-]{1,15}$')


def custom_prefix_strict(instance):
    """Ensure custom content follows strict naming style conventions.
    """
    for error in chain(custom_object_prefix_strict(instance),
                       custom_property_prefix_strict(instance),
                       custom_observable_object_prefix_strict(instance),
                       custom_object_extension_prefix_strict(instance),
                       custom_observable_properties_prefix_strict(instance)):
        yield error


def custom_prefix_lax(instance):
    """Ensure custom content follows lenient naming style conventions
    for forward-compatibility.
    """
    for error in chain(custom_object_prefix_lax(instance),
                       custom_property_prefix_lax(instance),
                       custom_observable_object_prefix_lax(instance),
                       custom_object_extension_prefix_lax(instance),
                       custom_observable_properties_prefix_lax(instance)):
        yield error


def custom_object_prefix_strict(instance):
    """Ensure custom objects follow strict naming style conventions.
    """
    if (instance['type'] not in enums.TYPES and
            instance['type'] not in enums.RESERVED_OBJECTS and
            not CUSTOM_TYPE_PREFIX_RE.match(instance['type'])):
        yield JSONError("Custom object type '%s' should start with 'x-' "
                        "followed by a source unique identifier (like a "
                        "domain name with dots replaced by hyphens), a hyphen "
                        "and then the name." % instance['type'],
                        instance['id'], 'custom-prefix')


def custom_object_prefix_lax(instance):
    """Ensure custom objects follow lenient naming style conventions
    for forward-compatibility.
    """
    if (instance['type'] not in enums.TYPES and
            instance['type'] not in enums.RESERVED_OBJECTS and
            not CUSTOM_TYPE_LAX_PREFIX_RE.match(instance['type'])):
        yield JSONError("Custom object type '%s' should start with 'x-' in "
                        "order to be compatible with future versions of the "
                        "STIX 2 specification." % instance['type'],
                        instance['id'], 'custom-prefix-lax')


def custom_property_prefix_strict(instance):
    """Ensure custom properties follow strict naming style conventions.

    Does not check property names in custom objects.
    """
    for prop_name in instance.keys():
        if (instance['type'] in enums.PROPERTIES and
                prop_name not in enums.PROPERTIES[instance['type']] and
                prop_name not in enums.RESERVED_PROPERTIES and
                not CUSTOM_PROPERTY_PREFIX_RE.match(prop_name)):

            yield JSONError("Custom property '%s' should have a type that "
                            "starts with 'x_' followed by a source unique "
                            "identifier (like a domain name with dots "
                            "replaced by hyphen), a hyphen and then the name."
                            % prop_name, instance['id'],
                            'custom-prefix')


def custom_property_prefix_lax(instance):
    """Ensure custom properties follow lenient naming style conventions
    for forward-compatibility.

    Does not check property names in custom objects.
    """
    for prop_name in instance.keys():
        if (instance['type'] in enums.PROPERTIES and
                prop_name not in enums.PROPERTIES[instance['type']] and
                prop_name not in enums.RESERVED_PROPERTIES and
                not CUSTOM_PROPERTY_LAX_PREFIX_RE.match(prop_name)):

            yield JSONError("Custom property '%s' should have a type that "
                            "starts with 'x_' in order to be compatible with "
                            "future versions of the STIX 2 specification." %
                            prop_name, instance['id'],
                            'custom-prefix-lax')


def open_vocab_values(instance):
    """Ensure that the values of all properties which use open vocabularies are
    in lowercase and use hyphens instead of spaces or underscores as word
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
                                    " lowercase and use hyphens instead of"
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
                                " and use hyphens instead of spaces or "
                                "underscores as word separators." % chain_name,
                                instance['id'], 'kill-chain-names')

            phase_name = phase['phase_name']
            if not phase_name.islower() or '_' in phase_name or ' ' in phase_name:
                yield JSONError("phase_name '%s' should be all lowercase and "
                                "use hyphens instead of spaces or underscores "
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
                       'industry-sector')


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
    try:
        r_source = re.search(r"(.+)--", instance['source_ref']).group(1)
        r_target = re.search(r"(.+)--", instance['target_ref']).group(1)
    except (AttributeError, TypeError):
        # Schemas already catch errors of these properties not being strings or
        # not containing the string '--'.
        return

    if (r_type in enums.COMMON_RELATIONSHIPS or
            r_source in enums.NON_SDOS or
            r_target in enums.NON_SDOS):
        # If all objects can have this relationship type, no more checks needed
        # Schemas already catch if source/target type cannot have relationship
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


def valid_hash_value(hashname):
    """Return true if given value is a valid, recommended hash name according
    to the STIX 2 specification.
    """
    custom_hash_prefix_re = re.compile(r"^x_")
    if hashname in enums.HASH_ALGO_OV or custom_hash_prefix_re.match(hashname):
        return True
    else:
        return False


@cyber_observable_check("2.0")
def vocab_hash_algo(instance):
    """Ensure objects with 'hashes' properties only use values from the
    hash-algo-ov vocabulary.
    """
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
                                        % (key, h), instance['id'], 'hash-algo')

            try:
                ads = obj['extensions']['ntfs-ext']['alternate_data_streams']
            except (KeyError, TypeError):
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
                                            % (key, h), instance['id'], 'hash-algo')

            try:
                head_hashes = obj['extensions']['windows-pebinary-ext']['file_header_hashes']
            except (KeyError, TypeError):
                pass
            else:
                for h in head_hashes:
                    if not (valid_hash_value(h)):
                        yield JSONError("Object '%s' has a Windows PE Binary "
                                        "File extension with a file header hash of "
                                        "'%s', which is not a value in the "
                                        "hash-algo-ov vocabulary nor a custom value "
                                        "prepended with 'x_'."
                                        % (key, h), instance['id'], 'hash-algo')

            try:
                hashes = obj['extensions']['windows-pebinary-ext']['optional_header']['hashes']
            except (KeyError, TypeError):
                pass
            else:
                for h in hashes:
                    if not (valid_hash_value(h)):
                        yield JSONError("Object '%s' has a Windows PE Binary "
                                        "File extension with an optional header that "
                                        "has a hash of '%s', which is not a value in "
                                        "the hash-algo-ov vocabulary nor a custom "
                                        "value prepended with 'x_'."
                                        % (key, h), instance['id'], 'hash-algo')

            try:
                sections = obj['extensions']['windows-pebinary-ext']['sections']
            except (KeyError, TypeError):
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
                                            % (key, h), instance['id'], 'hash-algo')

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
                                        % (key, h), instance['id'], 'hash-algo')


@cyber_observable_check("2.0")
def vocab_encryption_algo(instance):
    """Ensure file objects' 'encryption_algorithm' property is from the
    encryption-algo-ov vocabulary.
    """
    for key, obj in instance['objects'].items():
        if 'type' in obj and obj['type'] == 'file':
            try:
                enc_algo = obj['encryption_algorithm']
            except (KeyError, TypeError):
                continue
            if enc_algo not in enums.ENCRYPTION_ALGO_OV:
                yield JSONError("Object '%s' has an 'encryption_algorithm' of "
                                "'%s', which is not a value in the "
                                "encryption-algo-ov vocabulary."
                                % (key, enc_algo), instance['id'],
                                'encryption-algo')


@cyber_observable_check("2.0")
def vocab_windows_pebinary_type(instance):
    """Ensure file objects with the windows-pebinary-ext extension have a
    'pe-type' property that is from the windows-pebinary-type-ov vocabulary.
    """
    for key, obj in instance['objects'].items():
        if 'type' in obj and obj['type'] == 'file':
            try:
                pe_type = obj['extensions']['windows-pebinary-ext']['pe_type']
            except (KeyError, TypeError):
                continue
            if pe_type not in enums.WINDOWS_PEBINARY_TYPE_OV:
                yield JSONError("Object '%s' has a Windows PE Binary File "
                                "extension with a 'pe_type' of '%s', which is not a "
                                "value in the windows-pebinary-type-ov vocabulary."
                                % (key, pe_type), instance['id'],
                                'windows-pebinary-type')


@cyber_observable_check("2.0")
def vocab_account_type(instance):
    """Ensure a user-account objects' 'account-type' property is from the
    account-type-ov vocabulary.
    """
    for key, obj in instance['objects'].items():
        if 'type' in obj and obj['type'] == 'user-account':
            try:
                acct_type = obj['account_type']
            except (KeyError, TypeError):
                continue
            if acct_type not in enums.ACCOUNT_TYPE_OV:
                yield JSONError("Object '%s' is a User Account Object "
                                "with an 'account_type' of '%s', which is not a "
                                "value in the account-type-ov vocabulary."
                                % (key, acct_type), instance['id'], 'account-type')


@cyber_observable_check("2.0")
def observable_object_keys(instance):
    """Ensure observable-objects keys are non-negative integers.
    """
    digits_re = re.compile(r"^\d+$")
    for key in instance['objects']:
        if not digits_re.match(key):
            yield JSONError("'%s' is not a good key value. Observable Objects "
                            "should use non-negative integers for their keys."
                            % key, instance['id'], 'observable-object-keys')


def test_dict_keys(item, inst_id):
    """Recursively generate errors for incorrectly formatted cyber observable
    dictionary keys.
    """
    not_caps_re = re.compile(r"^[^A-Z]+$")
    for k, v in item.items():
        if not not_caps_re.match(k):
            yield JSONError("As a dictionary key for cyber observable "
                            "objects, '%s' should be lowercase." % k,
                            inst_id, 'observable-dictionary-keys')
        if not len(k) <= 30:
            yield JSONError("As a dictionary key for cyber observable "
                            "objects, '%s' should be no longer than 30 "
                            "characters long." % k, inst_id,
                            'observable-dictionary-keys')

        if type(v) is dict and k not in enums.OBSERVABLE_DICT_KEY_EXCEPTIONS:
            for error in test_dict_keys(v, inst_id):
                yield error


@cyber_observable_check("2.0")
def observable_dictionary_keys(instance):
    """Ensure dictionaries in the cyber observable layer have lowercase keys
    no longer than 30 characters.
    """
    for error in test_dict_keys(instance['objects'], instance['id']):
        yield error


@cyber_observable_check("2.0")
def custom_observable_object_prefix_strict(instance):
    """Ensure custom observable objects follow strict naming style conventions.
    """
    for key, obj in instance['objects'].items():
        if ('type' in obj and obj['type'] not in enums.OBSERVABLE_TYPES and
                obj['type'] not in enums.OBSERVABLE_RESERVED_OBJECTS and
                not CUSTOM_TYPE_PREFIX_RE.match(obj['type'])):
            yield JSONError("Custom Observable Object type '%s' should start "
                            "with 'x-' followed by a source unique identifier "
                            "(like a domain name with dots replaced by "
                            "hyphens), a hyphen and then the name."
                            % obj['type'], instance['id'],
                            'custom-prefix')


@cyber_observable_check("2.0")
def custom_observable_object_prefix_lax(instance):
    """Ensure custom observable objects follow naming style conventions.
    """
    for key, obj in instance['objects'].items():
        if ('type' in obj and obj['type'] not in enums.OBSERVABLE_TYPES and
                obj['type'] not in enums.OBSERVABLE_RESERVED_OBJECTS and
                not CUSTOM_TYPE_LAX_PREFIX_RE.match(obj['type'])):
            yield JSONError("Custom Observable Object type '%s' should start "
                            "with 'x-'."
                            % obj['type'], instance['id'],
                            'custom-prefix-lax')


@cyber_observable_check("2.0")
def custom_object_extension_prefix_strict(instance):
    """Ensure custom observable object extensions follow strict naming style
    conventions.
    """
    for key, obj in instance['objects'].items():
        if not ('extensions' in obj and isinstance(obj['extensions'], Mapping)
                and 'type' in obj and obj['type'] in enums.OBSERVABLE_EXTENSIONS):
            continue
        for ext_key in obj['extensions']:
            if (ext_key not in enums.OBSERVABLE_EXTENSIONS[obj['type']] and
                    not CUSTOM_TYPE_PREFIX_RE.match(ext_key)):
                yield JSONError("Custom Cyber Observable Object extension type"
                                " '%s' should start with 'x-' followed by a source "
                                "unique identifier (like a domain name with dots "
                                "replaced by hyphens), a hyphen and then the name."
                                % ext_key, instance['id'],
                                'custom-prefix')


@cyber_observable_check("2.0")
def custom_object_extension_prefix_lax(instance):
    """Ensure custom observable object extensions follow naming style
    conventions.
    """
    for key, obj in instance['objects'].items():
        if not ('extensions' in obj and 'type' in obj and
                obj['type'] in enums.OBSERVABLE_EXTENSIONS):
            continue
        for ext_key in obj['extensions']:
            if (ext_key not in enums.OBSERVABLE_EXTENSIONS[obj['type']] and
                    not CUSTOM_TYPE_LAX_PREFIX_RE.match(ext_key)):
                yield JSONError("Custom Cyber Observable Object extension type"
                                " '%s' should start with 'x-'."
                                % ext_key, instance['id'],
                                'custom-prefix-lax')


@cyber_observable_check("2.0")
def custom_observable_properties_prefix_strict(instance):
    """Ensure observable object custom properties follow strict naming style
    conventions.
    """
    for key, obj in instance['objects'].items():
        if 'type' not in obj:
            continue
        type_ = obj['type']

        for prop in obj:
            # Check objects' properties
            if (type_ in enums.OBSERVABLE_PROPERTIES and
                prop not in enums.OBSERVABLE_PROPERTIES[type_] and
                    not CUSTOM_PROPERTY_PREFIX_RE.match(prop)):
                yield JSONError("Cyber Observable Object custom property '%s' "
                                "should start with 'x_' followed by a source "
                                "unique identifier (like a domain name with "
                                "dots replaced by hyphens), a hyphen and then the"
                                " name."
                                % prop, instance['id'],
                                'custom-prefix')
            # Check properties of embedded cyber observable types
            if (type_ in enums.OBSERVABLE_EMBEDDED_PROPERTIES and
                    prop in enums.OBSERVABLE_EMBEDDED_PROPERTIES[type_]):
                for embed_prop in obj[prop]:
                    if isinstance(embed_prop, dict):
                        for embedded in embed_prop:
                            if (embedded not in enums.OBSERVABLE_EMBEDDED_PROPERTIES[type_][prop] and
                                    not CUSTOM_PROPERTY_PREFIX_RE.match(embedded)):
                                yield JSONError("Cyber Observable Object custom "
                                                "property '%s' in the %s property of "
                                                "%s object should start with 'x_' "
                                                "followed by a source unique "
                                                "identifier (like a domain name with "
                                                "dots replaced by hyphens), a hyphen and "
                                                "then the name."
                                                % (embedded, prop, type_), instance['id'],
                                                'custom-prefix')
                    elif (embed_prop not in enums.OBSERVABLE_EMBEDDED_PROPERTIES[type_][prop] and
                            not CUSTOM_PROPERTY_PREFIX_RE.match(embed_prop)):
                        yield JSONError("Cyber Observable Object custom "
                                        "property '%s' in the %s property of "
                                        "%s object should start with 'x_' "
                                        "followed by a source unique "
                                        "identifier (like a domain name with "
                                        "dots replaced by hyphens), a hyphen and "
                                        "then the name."
                                        % (embed_prop, prop, type_), instance['id'],
                                        'custom-prefix')

        # Check object extensions' properties
        if type_ in enums.OBSERVABLE_EXTENSIONS and 'extensions' in obj:
            for ext_key in obj['extensions']:

                if ext_key in enums.OBSERVABLE_EXTENSIONS[type_]:
                    for ext_prop in obj['extensions'][ext_key]:
                        if (ext_prop not in enums.OBSERVABLE_EXTENSION_PROPERTIES[ext_key] and
                                not CUSTOM_PROPERTY_PREFIX_RE.match(ext_prop)):
                            yield JSONError("Cyber Observable Object custom "
                                            "property '%s' in the %s extension "
                                            "should start with 'x_' followed by a "
                                            "source unique identifier (like a "
                                            "domain name with dots replaced by "
                                            "hyphens), a hyphen and then the name."
                                            % (ext_prop, ext_key), instance['id'],
                                            'custom-prefix')

                if ext_key in enums.OBSERVABLE_EXTENSIONS[type_]:
                    for ext_prop in obj['extensions'][ext_key]:
                        if (ext_key in enums.OBSERVABLE_EXTENSION_EMBEDDED_PROPERTIES and
                                ext_prop in enums.OBSERVABLE_EXTENSION_EMBEDDED_PROPERTIES[ext_key]):
                            for embed_prop in obj['extensions'][ext_key][ext_prop]:
                                if not (isinstance(embed_prop, Iterable) and not isinstance(embed_prop, string_types)):
                                    embed_prop = [embed_prop]
                                for p in embed_prop:
                                    if (p not in enums.OBSERVABLE_EXTENSION_EMBEDDED_PROPERTIES[ext_key][ext_prop] and
                                            not CUSTOM_PROPERTY_PREFIX_RE.match(p)):
                                        yield JSONError("Cyber Observable Object "
                                                        "custom property '%s' in the %s "
                                                        "property of the %s extension should "
                                                        "start with 'x_' followed by a source "
                                                        "unique identifier (like a domain name"
                                                        " with dots replaced by hyphens), a "
                                                        "hyphen and then the name."
                                                        % (p, ext_prop, ext_key), instance['id'],
                                                        'custom-prefix')


@cyber_observable_check("2.0")
def custom_observable_properties_prefix_lax(instance):
    """Ensure observable object custom properties follow naming style
    conventions.
    """
    for key, obj in instance['objects'].items():
        if 'type' not in obj:
            continue
        type_ = obj['type']

        for prop in obj:
            # Check objects' properties
            if (type_ in enums.OBSERVABLE_PROPERTIES and
                prop not in enums.OBSERVABLE_PROPERTIES[type_] and
                    not CUSTOM_PROPERTY_LAX_PREFIX_RE.match(prop)):
                yield JSONError("Cyber Observable Object custom property '%s' "
                                "should start with 'x_'."
                                % prop, instance['id'],
                                'custom-prefix-lax')
            # Check properties of embedded cyber observable types
            if (type_ in enums.OBSERVABLE_EMBEDDED_PROPERTIES and
                    prop in enums.OBSERVABLE_EMBEDDED_PROPERTIES[type_]):
                for embed_prop in obj[prop]:
                    if isinstance(embed_prop, dict):
                        for embedded in embed_prop:
                            if (embedded not in enums.OBSERVABLE_EMBEDDED_PROPERTIES[type_][prop] and
                                    not CUSTOM_PROPERTY_LAX_PREFIX_RE.match(embedded)):
                                yield JSONError("Cyber Observable Object custom "
                                                "property '%s' in the %s property of "
                                                "%s object should start with 'x_'."
                                                % (embedded, prop, type_), instance['id'],
                                                'custom-prefix-lax')
                    elif (embed_prop not in enums.OBSERVABLE_EMBEDDED_PROPERTIES[type_][prop] and
                            not CUSTOM_PROPERTY_LAX_PREFIX_RE.match(embed_prop)):
                        yield JSONError("Cyber Observable Object custom "
                                        "property '%s' in the %s property of "
                                        "%s object should start with 'x_'."
                                        % (embed_prop, prop, type_), instance['id'],
                                        'custom-prefix-lax')

        # Check object extensions' properties
        if type_ in enums.OBSERVABLE_EXTENSIONS and 'extensions' in obj:
            for ext_key in obj['extensions']:

                if ext_key in enums.OBSERVABLE_EXTENSIONS[type_]:
                    for ext_prop in obj['extensions'][ext_key]:
                        if (ext_prop not in enums.OBSERVABLE_EXTENSION_PROPERTIES[ext_key] and
                                not CUSTOM_PROPERTY_LAX_PREFIX_RE.match(ext_prop)):
                            yield JSONError("Cyber Observable Object custom "
                                            "property '%s' in the %s extension "
                                            "should start with 'x_'."
                                            % (ext_prop, ext_key), instance['id'],
                                            'custom-prefix-lax')

                if ext_key in enums.OBSERVABLE_EXTENSIONS[type_]:
                    for ext_prop in obj['extensions'][ext_key]:
                        if (ext_key in enums.OBSERVABLE_EXTENSION_EMBEDDED_PROPERTIES and
                                ext_prop in enums.OBSERVABLE_EXTENSION_EMBEDDED_PROPERTIES[ext_key]):
                            for embed_prop in obj['extensions'][ext_key][ext_prop]:
                                if not (isinstance(embed_prop, Iterable) and not isinstance(embed_prop, string_types)):
                                    embed_prop = [embed_prop]
                                for p in embed_prop:
                                    if (p not in enums.OBSERVABLE_EXTENSION_EMBEDDED_PROPERTIES[ext_key][ext_prop] and
                                            not CUSTOM_PROPERTY_LAX_PREFIX_RE.match(p)):
                                        yield JSONError("Cyber Observable Object "
                                                        "custom property '%s' in the %s "
                                                        "property of the %s extension should "
                                                        "start with 'x_'."
                                                        % (p, ext_prop, ext_key), instance['id'],
                                                        'custom-prefix-lax')


@cyber_observable_check("2.0")
def network_traffic_ports(instance):
    """Ensure network-traffic objects contain both src_port and dst_port.
    """
    for key, obj in instance['objects'].items():
        if ('type' in obj and obj['type'] == 'network-traffic' and
                ('src_port' not in obj or 'dst_port' not in obj)):
            yield JSONError("The Network Traffic object '%s' should contain "
                            "both the 'src_port' and 'dst_port' properties."
                            % key, instance['id'], 'network-traffic-ports')


@cyber_observable_check("2.0")
def mime_type(instance):
    """Ensure the 'mime_type' property of file objects comes from the Template
    column in the IANA media type registry.
    """
    mime_pattern = re.compile(r'^(application|audio|font|image|message|model'
                              '|multipart|text|video)/[a-zA-Z0-9.+_-]+')
    for key, obj in instance['objects'].items():
        if 'type' in obj and obj['type'] == 'file' and 'mime_type' in obj:
            if enums.media_types():
                if obj['mime_type'] not in enums.media_types():
                    yield JSONError("The 'mime_type' property of object '%s' "
                                    "('%s') should be an IANA registered MIME "
                                    "Type of the form 'type/subtype'."
                                    % (key, obj['mime_type']), instance['id'],
                                    'mime-type')
            else:
                info("Can't reach IANA website; using regex for mime types.")
                if not mime_pattern.match(obj['mime_type']):
                    yield JSONError("The 'mime_type' property of object '%s' "
                                    "('%s') should be an IANA MIME Type of the"
                                    " form 'type/subtype'."
                                    % (key, obj['mime_type']), instance['id'],
                                    'mime-type')


@cyber_observable_check("2.0")
def protocols(instance):
    """Ensure the 'protocols' property of network-traffic objects contains only
    values from the IANA Service Name and Transport Protocol Port Number
    Registry.
    """
    for key, obj in instance['objects'].items():
        if ('type' in obj and obj['type'] == 'network-traffic' and
                'protocols' in obj):
            for prot in obj['protocols']:
                if enums.protocols():
                    if prot not in enums.protocols():
                        yield JSONError("The 'protocols' property of object "
                                        "'%s' contains a value ('%s') not in "
                                        "IANA Service Name and Transport "
                                        "Protocol Port Number Registry."
                                        % (key, prot), instance['id'],
                                        'protocols')
                else:
                    info("Can't reach IANA website; using regex for protocols.")
                    if not PROTOCOL_RE.match(prot):
                        yield JSONError("The 'protocols' property of object "
                                        "'%s' contains a value ('%s') not in "
                                        "IANA Service Name and Transport "
                                        "Protocol Port Number Registry."
                                        % (key, prot), instance['id'],
                                        'protocols')


@cyber_observable_check("2.0")
def ipfix(instance):
    """Ensure the 'ipfix' property of network-traffic objects contains only
    values from the IANA IP Flow Information Export (IPFIX) Entities Registry.
    """
    ipf_pattern = re.compile(r'^[a-z][a-zA-Z0-9]+')
    for key, obj in instance['objects'].items():
        if ('type' in obj and obj['type'] == 'network-traffic' and
                'ipfix' in obj):
            for ipf in obj['ipfix']:
                if enums.ipfix():
                    if ipf not in enums.ipfix():
                        yield JSONError("The 'ipfix' property of object "
                                        "'%s' contains a key ('%s') not in "
                                        "IANA IP Flow Information Export "
                                        "(IPFIX) Entities Registry."
                                        % (key, ipf), instance['id'],
                                        'ipfix')
                else:
                    info("Can't reach IANA website; using regex for ipfix.")
                    if not ipf_pattern.match(ipf):
                        yield JSONError("The 'ipfix' property of object "
                                        "'%s' contains a key ('%s') not in "
                                        "IANA IP Flow Information Export "
                                        "(IPFIX) Entities Registry."
                                        % (key, ipf), instance['id'],
                                        'ipfix')


@cyber_observable_check("2.0")
def http_request_headers(instance):
    """Ensure the keys of the 'request_headers' property of the http-request-
    ext extension of network-traffic objects conform to the format for HTTP
    request headers. Use a regex because there isn't a definitive source.
    https://www.iana.org/assignments/message-headers/message-headers.xhtml does
    not differentiate between request and response headers, and leaves out
    several common non-standard request fields listed elsewhere.
    """
    for key, obj in instance['objects'].items():
        if 'type' in obj and obj['type'] == 'network-traffic':
            try:
                headers = obj['extensions']['http-request-ext']['request_header']
            except (KeyError, TypeError):
                continue

            for hdr in headers:
                if hdr not in enums.HTTP_REQUEST_HEADERS:
                    yield JSONError("The 'request_header' property of object "
                                    "'%s' contains an invalid HTTP request "
                                    "header ('%s')."
                                    % (key, hdr), instance['id'],
                                    'http-request-headers')


@cyber_observable_check("2.0")
def socket_options(instance):
    """Ensure the keys of the 'options' property of the socket-ext extension of
    network-traffic objects are only valid socket options (SO_*).
    """
    for key, obj in instance['objects'].items():
        if 'type' in obj and obj['type'] == 'network-traffic':
            try:
                options = obj['extensions']['socket-ext']['options']
            except (KeyError, TypeError):
                continue

            for opt in options:
                if opt not in enums.SOCKET_OPTIONS:
                    yield JSONError("The 'options' property of object '%s' "
                                    "contains a key ('%s') that is not a valid"
                                    " socket option (SO_*)."
                                    % (key, opt), instance['id'], 'socket-options')


@cyber_observable_check("2.0")
def pdf_doc_info(instance):
    """Ensure the keys of the 'document_info_dict' property of the pdf-ext
    extension of file objects are only valid PDF Document Information
    Dictionary Keys.
    """
    for key, obj in instance['objects'].items():
        if 'type' in obj and obj['type'] == 'file':
            try:
                did = obj['extensions']['pdf-ext']['document_info_dict']
            except (KeyError, TypeError):
                continue

            for elem in did:
                if elem not in enums.PDF_DID:
                    yield JSONError("The 'document_info_dict' property of "
                                    "object '%s' contains a key ('%s') that is"
                                    " not a valid PDF Document Information "
                                    "Dictionary key."
                                    % (key, elem), instance['id'],
                                    'pdf-doc-info')


@cyber_observable_check("2.0")
def windows_process_priority_format(instance):
    """Ensure the 'priority' property of windows-process-ext ends in '_CLASS'.
    """
    class_suffix_re = re.compile(r'.+_CLASS$')
    for key, obj in instance['objects'].items():
        if 'type' in obj and obj['type'] == 'process':
            try:
                priority = obj['extensions']['windows-process-ext']['priority']
            except (KeyError, TypeError):
                continue
            if not class_suffix_re.match(priority):
                yield JSONError("The 'priority' property of object '%s' should"
                                " end in '_CLASS'." % key, instance['id'],
                                'windows-process-priority-format')


@cyber_observable_check("2.0")
def hash_length(instance):
    """Ensure keys in 'hashes'-type properties are no more than 30 characters long.
    """
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
                    if len(h) > 30:
                        yield JSONError("Object '%s' has a 'hashes' dictionary"
                                        " with a hash of type '%s', which is "
                                        "longer than 30 characters."
                                        % (key, h), instance['id'], 'hash-algo')

            try:
                ads = obj['extensions']['ntfs-ext']['alternate_data_streams']
            except (KeyError, TypeError):
                pass
            else:
                for datastream in ads:
                    if 'hashes' not in datastream:
                        continue
                    for h in datastream['hashes']:
                        if len(h) > 30:
                            yield JSONError("Object '%s' has an NTFS extension"
                                            " with an alternate data stream that has a"
                                            " 'hashes' dictionary with a hash of type "
                                            "'%s', which is longer than 30 "
                                            "characters."
                                            % (key, h), instance['id'], 'hash-algo')

            try:
                head_hashes = obj['extensions']['windows-pebinary-ext']['file_header_hashes']
            except (KeyError, TypeError):
                pass
            else:
                for h in head_hashes:
                    if len(h) > 30:
                        yield JSONError("Object '%s' has a Windows PE Binary "
                                        "File extension with a file header hash of "
                                        "'%s', which is longer than 30 "
                                        "characters."
                                        % (key, h), instance['id'], 'hash-algo')

            try:
                hashes = obj['extensions']['windows-pebinary-ext']['optional_header']['hashes']
            except (KeyError, TypeError):
                pass
            else:
                for h in hashes:
                    if len(h) > 30:
                        yield JSONError("Object '%s' has a Windows PE Binary "
                                        "File extension with an optional header that "
                                        "has a hash of '%s', which is longer "
                                        "than 30 characters."
                                        % (key, h), instance['id'], 'hash-algo')

            try:
                sections = obj['extensions']['windows-pebinary-ext']['sections']
            except (KeyError, TypeError):
                pass
            else:
                for s in sections:
                    if 'hashes' not in s:
                        continue
                    for h in s['hashes']:
                        if len(h) > 30:
                            yield JSONError("Object '%s' has a Windows PE "
                                            "Binary File extension with a section that"
                                            " has a hash of '%s', which is "
                                            "longer than 30 characters."
                                            % (key, h), instance['id'], 'hash-algo')

        elif obj['type'] == 'artifact' or obj['type'] == 'x509-certificate':
            try:
                hashes = obj['hashes']
            except (KeyError, TypeError):
                pass
            else:
                for h in hashes:
                    if len(h) > 30:
                        yield JSONError("Object '%s' has a 'hashes' dictionary"
                                        " with a hash of type '%s', which is "
                                        "longer than 30 characters."
                                        % (key, h), instance['id'], 'hash-algo')


def extref_hashes(instance):
    if 'external_references' in instance:
        for extref in instance['external_references']:
            if 'url' in extref and 'hashes' not in extref:
                src = extref['source_name'] if 'source_name' in extref else ''
                return JSONError("External reference '%s' has a URL but no hash."
                                 % src, instance['id'], 'extref-hashes')


def enforce_relationship_refs(instance):
    """Ensures that all SDOs being referenced by the SRO are contained
    within the same bundle"""
    if instance['type'] != 'bundle' or 'objects' not in instance:
        return

    rel_references = set()

    """Find and store all ids"""
    for obj in instance['objects']:
        if obj['type'] != 'relationship':
            rel_references.add(obj['id'])

    """Check if id has been encountered"""
    for obj in instance['objects']:
        if obj['type'] == 'relationship':
            if obj['source_ref'] not in rel_references:
                yield JSONError("Relationship object %s makes reference to %s "
                                "Which is not found in current bundle "
                                % (obj['id'], obj['source_ref']), 'enforce-relationship-refs')

            if obj['target_ref'] not in rel_references:
                yield JSONError("Relationship object %s makes reference to %s "
                                "Which is not found in current bundle "
                                % (obj['id'], obj['target_ref']), 'enforce-relationship-refs')


def duplicate_ids(instance):
    """Ensure objects with duplicate IDs have different `modified` timestamps.
    """
    if instance['type'] != 'bundle' or 'objects' not in instance:
        return

    unique_ids = {}
    for obj in instance['objects']:
        if 'id' not in obj or 'modified' not in obj:
            continue
        elif obj['id'] not in unique_ids:
            unique_ids[obj['id']] = obj['modified']
        elif obj['modified'] == unique_ids[obj['id']]:
            yield JSONError("Duplicate ID '%s' has identical `modified` timestamp."
                            " If they are different versions of the same object, "
                            "they should have different `modified` properties."
                            % obj['id'], instance['id'], 'duplicate-ids')


def types_strict(instance):
    """Ensure that no custom object types are used, but only the official ones
    from the specification.
    """
    if instance['type'] not in enums.TYPES:
        yield JSONError("Object type '%s' is not one of those defined in the"
                        " specification." % instance['type'], instance['id'])

    if has_cyber_observable_data(instance):
        for key, obj in instance['objects'].items():
            if 'type' in obj and obj['type'] not in enums.OBSERVABLE_TYPES:
                yield JSONError("Observable object %s is type '%s' which is "
                                "not one of those defined in the "
                                "specification."
                                % (key, obj['type']), instance['id'])

    if instance['type'] == 'indicator' and 'pattern' in instance:
        pattern = instance['pattern']
        if isinstance(pattern, string_types):
            p = Pattern(pattern)
            inspection = p.inspect().comparisons
            for objtype in inspection:
                if objtype not in enums.OBSERVABLE_TYPES:
                    yield PatternError("'%s' is not a valid stix observable type"
                                       % objtype, instance['id'])


def properties_strict(instance):
    """Ensure that no custom properties are used, but only the official ones
    from the specification.
    """
    if instance['type'] not in enums.TYPES:
        return  # only check properties for official objects

    defined_props = enums.PROPERTIES.get(instance['type'], [])
    for prop in instance.keys():
        if prop not in defined_props:
            yield JSONError("Property '%s' is not one of those defined in the"
                            " specification." % prop, instance['id'])

    if has_cyber_observable_data(instance):
        for key, obj in instance['objects'].items():
            type_ = obj.get('type', '')
            if type_ not in enums.OBSERVABLE_PROPERTIES:
                continue  # custom observable types handled outside this function
            observable_props = enums.OBSERVABLE_PROPERTIES.get(type_, [])
            embedded_props = enums.OBSERVABLE_EMBEDDED_PROPERTIES.get(type_, {})
            extensions = enums.OBSERVABLE_EXTENSIONS.get(type_, [])
            for prop in obj.keys():
                if prop not in observable_props:
                    yield JSONError("Property '%s' is not one of those defined in the"
                                    " specification for %s objects."
                                    % (prop, type_), instance['id'])
                # Check properties of embedded cyber observable types
                elif prop in embedded_props:
                    embedded_prop_keys = embedded_props.get(prop, [])
                    for embedded_key in obj[prop]:
                        if isinstance(embedded_key, dict):
                            for embedded in embedded_key:
                                if embedded not in embedded_prop_keys:
                                    yield JSONError("Property '%s' is not one of those defined in the"
                                                    " specification for the %s property in %s objects."
                                                    % (embedded, prop, type_), instance['id'])
                        elif embedded_key not in embedded_prop_keys:
                            yield JSONError("Property '%s' is not one of those defined in the"
                                            " specification for the %s property in %s objects."
                                            % (embedded_key, prop, type_), instance['id'])

            # Check properties of embedded cyber observable types
            for ext_key in obj.get('extensions', {}):
                if ext_key not in extensions:
                    continue  # don't check custom extensions
                extension_props = enums.OBSERVABLE_EXTENSION_PROPERTIES[ext_key]
                for ext_prop in obj['extensions'][ext_key]:
                    if ext_prop not in extension_props:
                        yield JSONError("Property '%s' is not one of those defined in the"
                                        " specification for the %s extension in %s objects."
                                        % (ext_prop, ext_key, type_), instance['id'])
                    embedded_ext_props = enums.OBSERVABLE_EXTENSION_EMBEDDED_PROPERTIES.get(ext_key, {}).get(ext_prop, [])
                    if embedded_ext_props:
                        for embed_ext_prop in obj['extensions'][ext_key].get(ext_prop, []):
                            if embed_ext_prop not in embedded_ext_props:
                                yield JSONError("Property '%s' in the %s property of the %s extension "
                                                "is not one of those defined in the specification."
                                                % (embed_ext_prop, ext_prop, ext_key), instance['id'])

    if instance['type'] == 'indicator' and 'pattern' in instance:
        pattern = instance['pattern']
        if isinstance(pattern, string_types):
            p = Pattern(pattern)
            inspection = p.inspect().comparisons
            for objtype, expression_list in inspection.items():
                for exp in expression_list:
                    path = exp[0]
                    # Get the property name without list index, dictionary key, or referenced object property
                    prop = path[0]
                    if objtype in enums.OBSERVABLE_PROPERTIES and prop not in enums.OBSERVABLE_PROPERTIES[objtype]:
                        yield PatternError("'%s' is not a valid property for '%s' objects"
                                           % (prop, objtype), instance['id'])


# Mapping of check names to the functions which perform the checks
CHECKS = {
    'all': [
        custom_object_prefix_strict,
        custom_property_prefix_strict,
        open_vocab_values,
        kill_chain_phase_names,
        observable_object_keys,
        observable_dictionary_keys,
        custom_observable_object_prefix_strict,
        custom_object_extension_prefix_strict,
        custom_observable_properties_prefix_strict,
        windows_process_priority_format,
        hash_length,
        vocab_marking_definition,
        relationships_strict,
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
        vocab_hash_algo,
        vocab_encryption_algo,
        vocab_windows_pebinary_type,
        vocab_account_type,
        mime_type,
        protocols,
        ipfix,
        http_request_headers,
        socket_options,
        pdf_doc_info,
        network_traffic_ports,
        extref_hashes,
        duplicate_ids,
    ],
    'format-checks': [
        custom_object_prefix_strict,
        custom_property_prefix_strict,
        open_vocab_values,
        kill_chain_phase_names,
        observable_object_keys,
        observable_dictionary_keys,
        custom_observable_object_prefix_strict,
        custom_object_extension_prefix_strict,
        custom_observable_properties_prefix_strict,
        windows_process_priority_format,
        hash_length,
    ],
    'custom-prefix': custom_prefix_strict,
    'custom-prefix-lax': custom_prefix_lax,
    'open-vocab-format': open_vocab_values,
    'kill-chain-names': kill_chain_phase_names,
    'observable-object-keys': observable_object_keys,
    'observable-dictionary-keys': observable_dictionary_keys,
    'windows-process-priority-format': windows_process_priority_format,
    'hash-length': hash_length,
    'approved-values': [
        vocab_marking_definition,
        relationships_strict,
        duplicate_ids,
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
        vocab_hash_algo,
        vocab_encryption_algo,
        vocab_windows_pebinary_type,
        vocab_account_type,
        mime_type,
        protocols,
        ipfix,
        http_request_headers,
        socket_options,
        pdf_doc_info,
    ],
    'marking-definition-type': vocab_marking_definition,
    'relationship-types': relationships_strict,
    'duplicate-ids': duplicate_ids,
    'enforce_relationship_refs': enforce_relationship_refs,
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
        vocab_hash_algo,
        vocab_encryption_algo,
        vocab_windows_pebinary_type,
        vocab_account_type,
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
    'hash-algo': vocab_hash_algo,
    'encryption-algo': vocab_encryption_algo,
    'windows-pebinary-type': vocab_windows_pebinary_type,
    'account-type': vocab_account_type,
    'all-external-sources': [
        mime_type,
        protocols,
        ipfix,
        http_request_headers,
        socket_options,
        pdf_doc_info,
    ],
    'mime-type': mime_type,
    'protocols': protocols,
    'ipfix': ipfix,
    'http-request-headers': http_request_headers,
    'socket-options': socket_options,
    'pdf-doc-info': pdf_doc_info,
    'network-traffic-ports': network_traffic_ports,
    'extref-hashes': extref_hashes,
}


def list_shoulds(options):
    """Construct the list of 'SHOULD' validators to be run by the validator.
    """
    validator_list = []
    # --enforce_refs
    # enable checking references in bundles if option selected
    if options.enforce_refs is True:
        validator_list.append(CHECKS['enforce_relationship_refs'])

    # --strict-types
    if options.strict_types:
        validator_list.append(types_strict)

    # --strict-properties
    if options.strict_properties:
        validator_list.append(properties_strict)

    # Default: enable all
    if not options.disabled and not options.enabled:
        validator_list.extend(CHECKS['all'])
        return validator_list

    # --disable
    # Add SHOULD requirements to the list unless disabled
    if options.disabled:
        if 'all' not in options.disabled:
            if 'format-checks' not in options.disabled:
                if 'custom-prefix' not in options.disabled:
                    validator_list.append(CHECKS['custom-prefix'])
                elif 'custom-prefix-lax' not in options.disabled:
                    validator_list.append(CHECKS['custom-prefix-lax'])
                if 'open-vocab-format' not in options.disabled:
                    validator_list.append(CHECKS['open-vocab-format'])
                if 'kill-chain-names' not in options.disabled:
                    validator_list.append(CHECKS['kill-chain-names'])
                if 'observable-object-keys' not in options.disabled:
                    validator_list.append(CHECKS['observable-object-keys'])
                if 'observable-dictionary-keys' not in options.disabled:
                    validator_list.append(CHECKS['observable-dictionary-keys'])
                if 'windows-process-priority-format' not in options.disabled:
                    validator_list.append(CHECKS['windows-process-priority-format'])
                if 'hash-length' not in options.disabled:
                    validator_list.append(CHECKS['hash-length'])

            if 'approved-values' not in options.disabled:
                if 'marking-definition-type' not in options.disabled:
                    validator_list.append(CHECKS['marking-definition-type'])
                if 'relationship-types' not in options.disabled:
                    validator_list.append(CHECKS['relationship-types'])
                if 'duplicate-ids' not in options.disabled:
                    validator_list.append(CHECKS['duplicate-ids'])
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
                    if 'hash-algo' not in options.disabled:
                        validator_list.append(CHECKS['hash-algo'])
                    if 'encryption-algo' not in options.disabled:
                        validator_list.append(CHECKS['encryption-algo'])
                    if 'windows-pebinary-type' not in options.disabled:
                        validator_list.append(CHECKS['windows-pebinary-type'])
                    if 'account-type' not in options.disabled:
                        validator_list.append(CHECKS['account-type'])
                if 'all-external-sources' not in options.disabled:
                    if 'mime-type' not in options.disabled:
                        validator_list.append(CHECKS['mime-type'])
                    if 'protocols' not in options.disabled:
                        validator_list.append(CHECKS['protocols'])
                    if 'ipfix' not in options.disabled:
                        validator_list.append(CHECKS['ipfix'])
                    if 'http-request-headers' not in options.disabled:
                        validator_list.append(CHECKS['http-request-headers'])
                    if 'socket-options' not in options.disabled:
                        validator_list.append(CHECKS['socket-options'])
                    if 'pdf-doc-info' not in options.disabled:
                        validator_list.append(CHECKS['pdf-doc-info'])

            if 'network-traffic-ports' not in options.disabled:
                validator_list.append(CHECKS['network-traffic-ports'])
            if 'extref-hashes' not in options.disabled:
                validator_list.append(CHECKS['extref-hashes'])

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
                raise JSONError("%s is not a valid check!" % check)

    return validator_list
