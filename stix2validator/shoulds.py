"""Recommended (SHOULD) requirement checking functions
"""

import re
from collections import Iterable
from six import string_types
from . import enums
from .util import cyber_observable_check
from .errors import JSONError


def custom_object_prefix_strict(instance):
    """Ensure custom objects follow strict naming style conventions.
    """
    if (instance['type'] not in enums.TYPES and
            instance['type'] not in enums.RESERVED_OBJECTS and
            not re.match("^x\-.+\-.+$", instance['type'])):
        yield JSONError("Custom object type '%s' should start with 'x-' "
                        "followed by a source unique identifier (like a "
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
            r_source in enums.NON_SDOS or
            r_target in enums.NON_SDOS):
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


def test_dict_keys(item, inst_id):
    """Recursively generate errors for incorrectly formatted cyber observable
    dictionary keys.
    """
    for k, v in item.items():
        if not re.match("^[^A-Z]+$", k):
            yield JSONError("As a dictionary key for cyber observable "
                            "objects, '%s' should be lowercase." % k,
                            inst_id)
        if not len(k) <= 30:
            yield JSONError("As a dictionary key for cyber observable "
                            "objects, '%s' should be no longer than 30 "
                            "characters long." % k, inst_id)

        if type(v) is dict and k not in enums.OBSERVABLE_DICT_KEY_EXCEPTIONS:
            for error in test_dict_keys(v, inst_id):
                yield error


@cyber_observable_check
def observable_dictionary_keys(instance):
    """Ensure dictionaries in the cyber observable layer have lowercase keys
    no longer than 30 characters.
    """
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


@cyber_observable_check
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


@cyber_observable_check
def vocab_encryption_algo(instance):
    """Ensure file objects' 'encryption_algorithm' property is from the
    encryption-algo-ov vocabulary.
    """
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


@cyber_observable_check
def vocab_windows_pebinary_type(instance):
    """Ensure file objects with the windows-pebinary-ext extension have a
    'pe-type' property that is from the account-type-ov vocabulary.
    """
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


@cyber_observable_check
def vocab_account_type(instance):
    """Ensure a user-account objects' 'account-type' property is from the
    account-type-ov vocabulary.
    """
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


@cyber_observable_check
def observable_object_keys(instance):
    """Ensure observable-objects keys are non-negative integers.
    """
    for key in instance['objects']:
        if not re.match("^\d+$", key):
            yield JSONError("'%s' is not a good key value. Observable Objects "
                "should use non-negative integers for their keys."
                % key, instance['id'])


@cyber_observable_check
def custom_observable_object_prefix_strict(instance):
    """Ensure custom observable objects follow strict naming style conventions.
    """
    for key, obj in instance['objects'].items():
        if ('type' in obj and obj['type'] not in enums.OBSERVABLE_TYPES and
                obj['type'] not in enums.OBSERVABLE_RESERVED_OBJECTS and
                not re.match("^x\-.+\-.+$", obj['type'])):
            yield JSONError("Custom Observable Object type '%s' should start "
                    "with 'x-' followed by a source unique identifier (like a "
                    "domain name with dots replaced by dashes), a dash and "
                    "then the name."
                    % obj['type'], instance['id'])


@cyber_observable_check
def custom_observable_object_prefix_lax(instance):
    """Ensure custom observable objects follow naming style conventions.
    """
    for key, obj in instance['objects'].items():
        if ('type' in obj and obj['type'] not in enums.OBSERVABLE_TYPES and
                obj['type'] not in enums.OBSERVABLE_RESERVED_OBJECTS and
                not re.match("^x\-.+$", obj['type'])):
            yield JSONError("Custom Observable Object type '%s' should start "
                    "with 'x-'."
                    % obj['type'], instance['id'])


@cyber_observable_check
def custom_object_extension_prefix_strict(instance):
    """Ensure custom observable objects follow strict naming style conventions.
    """
    for key, obj in instance['objects'].items():
        if not ('extensions' in obj and 'type' in obj and
                obj['type'] in enums.OBSERVABLE_EXTENSIONS):
            continue
        for ext_key in obj['extensions']:
            if (ext_key not in enums.OBSERVABLE_EXTENSIONS[obj['type']] and
                    not re.match("^x\-.+\-.+$", ext_key)):
                yield JSONError("Custom Cyber Observable Object extension type"
                        " '%s' should start with 'x-' followed by a source "
                        "unique identifier (like a domain name with dots "
                        "replaced by dashes), a dash and then the name."
                        % ext_key, instance['id'])


@cyber_observable_check
def custom_object_extension_prefix_lax(instance):
    """Ensure custom observable objects follow naming style conventions.
    """
    for key, obj in instance['objects'].items():
        if not ('extensions' in obj and 'type' in obj and
                obj['type'] in enums.OBSERVABLE_EXTENSIONS):
            continue
        for ext_key in obj['extensions']:
            if (ext_key not in enums.OBSERVABLE_EXTENSIONS[obj['type']] and
                    not re.match("^x\-.+$", ext_key)):
                yield JSONError("Custom Cyber Observable Object extension type"
                                " '%s' should start with 'x-'."
                                % ext_key, instance['id'])


@cyber_observable_check
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
                    not re.match("^x\-.+\-.+$", prop)):
                yield JSONError("Cyber Observable Object custom property '%s' "
                                "should start with 'x-' followed by a source "
                                "unique identifier (like a domain name with "
                                "dots replaced by dashes), a dash and then the"
                                " name."
                                % prop, instance['id'])
            # Check properties of embedded cyber observable types
            if (type_ in enums.OBSERVABLE_EMBEDED_PROPERTIES and
                    prop in enums.OBSERVABLE_EMBEDED_PROPERTIES[type_]):
                for embed_prop in obj[prop]:
                    if isinstance(embed_prop, dict):
                        for embedded in embed_prop:
                            if (embedded not in enums.OBSERVABLE_EMBEDED_PROPERTIES[type_][prop] and
                                    not re.match("^x\-.+\-.+$", embedded)):
                                yield JSONError("Cyber Observable Object custom "
                                                "property '%s' in the %s property of a"
                                                " %s object should start with 'x-' "
                                                "followed by a source unique "
                                                "identifier (like a domain name with "
                                                "dots replaced by dashes), a dash and "
                                                "then the name."
                                                % (embedded, prop, type_), instance['id'])
                    elif (embed_prop not in enums.OBSERVABLE_EMBEDED_PROPERTIES[type_][prop] and
                            not re.match("^x\-.+\-.+$", embed_prop)):
                        yield JSONError("Cyber Observable Object custom "
                                        "property '%s' in the %s property of a"
                                        " %s object should start with 'x-' "
                                        "followed by a source unique "
                                        "identifier (like a domain name with "
                                        "dots replaced by dashes), a dash and "
                                        "then the name."
                                        % (embed_prop, prop, type_), instance['id'])

        # Check object extensions' properties
        if (type_ in enums.OBSERVABLE_EXTENSIONS and 'extensions' in obj):
            for ext_key in obj['extensions']:

                if ext_key in enums.OBSERVABLE_EXTENSIONS[type_]:
                    for ext_prop in obj['extensions'][ext_key]:
                        if (ext_prop not in enums.OBSERVABLE_EXTENSION_PROPERTIES[ext_key] and
                                not re.match("^x\-.+\-.+$", ext_prop)):
                            yield JSONError("Cyber Observable Object custom "
                                            "property '%s' in the %s extension "
                                            "should start with 'x-' followed by a "
                                            "source unique identifier (like a "
                                            "domain name with dots replaced by "
                                            "dashes), a dash and then the name."
                                            % (ext_prop, ext_key), instance['id'])

                if ext_key in enums.OBSERVABLE_EXTENSIONS[type_]:
                    for ext_prop in obj['extensions'][ext_key]:
                        if (ext_key in enums.OBSERVABLE_EXTENSION_EMBEDED_PROPERTIES and
                                ext_prop in enums.OBSERVABLE_EXTENSION_EMBEDED_PROPERTIES[ext_key]):
                            for embed_prop in obj['extensions'][ext_key][ext_prop]:
                                if not (isinstance(embed_prop, Iterable) and not isinstance(embed_prop, string_types)):
                                    embed_prop = [embed_prop]
                                for p in embed_prop:
                                    if (p not in enums.OBSERVABLE_EXTENSION_EMBEDED_PROPERTIES[ext_key][ext_prop] and
                                            not re.match("^x\-.+\-.+$", p)):
                                        yield JSONError("Cyber Observable Object "
                                                "custom property '%s' in the %s "
                                                "property of the %s extension should "
                                                "start with 'x-' followed by a source "
                                                "unique identifier (like a domain name"
                                                " with dots replaced by dashes), a "
                                                "dash and then the name."
                                                % (p, ext_prop, ext_key), instance['id'])


@cyber_observable_check
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
                    not re.match("^x\-.+$", prop)):
                yield JSONError("Cyber Observable Object custom property '%s' "
                                "should start with 'x-'."
                                % prop, instance['id'])
            # Check properties of embedded cyber observable types
            if (type_ in enums.OBSERVABLE_EMBEDED_PROPERTIES and
                    prop in enums.OBSERVABLE_EMBEDED_PROPERTIES[type_]):
                for embed_prop in obj[prop]:
                    if isinstance(embed_prop, dict):
                        for embedded in embed_prop:
                            if (embedded not in enums.OBSERVABLE_EMBEDED_PROPERTIES[type_][prop] and
                                    not re.match("^x\-.+$", embedded)):
                                yield JSONError("Cyber Observable Object custom "
                                                "property '%s' in the %s property of a"
                                                " %s object should start with 'x-'."
                                                % (embedded, prop, type_), instance['id'])
                    elif (embed_prop not in enums.OBSERVABLE_EMBEDED_PROPERTIES[type_][prop] and
                            not re.match("^x\-.+$", embed_prop)):
                        yield JSONError("Cyber Observable Object custom "
                                        "property '%s' in the %s property of a"
                                        " %s object should start with 'x-'."
                                        % (embed_prop, prop, type_), instance['id'])

        # Check object extensions' properties
        if (type_ in enums.OBSERVABLE_EXTENSIONS and 'extensions' in obj):
            for ext_key in obj['extensions']:

                if ext_key in enums.OBSERVABLE_EXTENSIONS[type_]:
                    for ext_prop in obj['extensions'][ext_key]:
                        if (ext_prop not in enums.OBSERVABLE_EXTENSION_PROPERTIES[ext_key] and
                                not re.match("^x\-.+$", ext_prop)):
                            yield JSONError("Cyber Observable Object custom "
                                            "property '%s' in the %s extension "
                                            "should start with 'x-'."
                                            % (ext_prop, ext_key), instance['id'])

                if ext_key in enums.OBSERVABLE_EXTENSIONS[type_]:
                    for ext_prop in obj['extensions'][ext_key]:
                        if (ext_key in enums.OBSERVABLE_EXTENSION_EMBEDED_PROPERTIES and
                                ext_prop in enums.OBSERVABLE_EXTENSION_EMBEDED_PROPERTIES[ext_key]):
                            for embed_prop in obj['extensions'][ext_key][ext_prop]:
                                if not (isinstance(embed_prop, Iterable) and not isinstance(embed_prop, string_types)):
                                    embed_prop = [embed_prop]
                                for p in embed_prop:
                                    if (p not in enums.OBSERVABLE_EXTENSION_EMBEDED_PROPERTIES[ext_key][ext_prop] and
                                            not re.match("^x\-.+$", p)):
                                        yield JSONError("Cyber Observable Object "
                                                "custom property '%s' in the %s "
                                                "property of the %s extension should "
                                                "start with 'x-'."
                                                % (p, ext_prop, ext_key), instance['id'])


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


def list_shoulds(options):
    """Construct the list of 'SHOULD' validators to be run by the validator.
    """
    validator_list = []

    # TODO: make these optional, and add check codes to all of them
    validator_list.extend([
        observable_dictionary_keys,
        vocab_hash_algo,
        vocab_encryption_algo,
        vocab_windows_pebinary_type,
        vocab_account_type,
        observable_object_keys,
        custom_observable_object_prefix_strict,
        custom_observable_object_prefix_lax,
        custom_object_extension_prefix_strict,
        custom_object_extension_prefix_lax,
        custom_observable_properties_prefix_strict
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
                raise JSONError("%s is not a valid check!" % check)

    return validator_list
