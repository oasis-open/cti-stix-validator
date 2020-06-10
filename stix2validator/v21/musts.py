"""Mandatory (MUST) requirement checking functions
"""
import collections
import operator
import re
import uuid

from cpe import CPE
from dateutil import parser
from six import string_types
from stix2patterns.v21.pattern import Pattern
from stix2patterns.validator import run_validator as pattern_validator

from . import enums
from ..errors import PatternError
from ..output import info
from ..util import cyber_observable_check, has_cyber_observable_data
from .errors import JSONError

TYPE_FORMAT_RE = re.compile(r'^\-?[a-z0-9]+(-[a-z0-9]+)*\-?$')
PROPERTY_FORMAT_RE = re.compile(r'^[a-z0-9_]{3,250}$')
CUSTOM_TYPE_PREFIX_RE = re.compile(r"^x\-.+\-.+$")
CUSTOM_TYPE_LAX_PREFIX_RE = re.compile(r"^x\-.+$")
CUSTOM_PROPERTY_PREFIX_RE = re.compile(r"^x_.+_.+$")
CUSTOM_PROPERTY_LAX_PREFIX_RE = re.compile(r"^x_.+$")
CUSTOM_EXT_PREFIX_RE = re.compile(r"^x\-.+\-.+\-ext$")
CUSTOM_EXT_LAX_PREFIX_RE = re.compile(r"^x\-.+\-ext$")


def timestamp(instance):
    """Ensure timestamps contain sane months, days, hours, minutes, seconds.
    """
    ts_re = re.compile(r"^[0-9]{4}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]+)?Z$")
    timestamp_props = ['created', 'modified']
    if instance['type'] in enums.TIMESTAMP_PROPERTIES:
        timestamp_props += enums.TIMESTAMP_PROPERTIES[instance['type']]

    for tprop in timestamp_props:
        if tprop in instance and ts_re.match(instance[tprop]):
            # Don't raise an error if schemas will catch it
            try:
                parser.parse(instance[tprop])
            except ValueError as e:
                yield JSONError("'%s': '%s' is not a valid timestamp: %s"
                                % (tprop, instance[tprop], str(e)), instance['id'])

    if has_cyber_observable_data(instance, "2.1"):
        if instance['type'] == 'observable-data':
            for key, obj in instance['objects'].items():
                if 'type' not in obj:
                    continue
                if obj['type'] in enums.TIMESTAMP_OBSERVABLE_PROPERTIES:
                    for tprop in enums.TIMESTAMP_OBSERVABLE_PROPERTIES[obj['type']]:
                        if tprop in obj and ts_re.match(obj[tprop]):
                            # Don't raise an error if schemas will catch it
                            try:
                                parser.parse(obj[tprop])
                            except ValueError as e:
                                yield JSONError("'%s': '%s': '%s' is not a valid timestamp: %s"
                                                % (obj['type'], tprop, obj[tprop], str(e)), instance['id'])
                if obj['type'] in enums.TIMESTAMP_EMBEDDED_PROPERTIES:
                    for embed in enums.TIMESTAMP_EMBEDDED_PROPERTIES[obj['type']]:
                        if embed in obj and isinstance(obj[embed], collections.Mapping):
                            for tprop in enums.TIMESTAMP_EMBEDDED_PROPERTIES[obj['type']][embed]:
                                if embed == 'extensions':
                                    for ext in obj[embed]:
                                        if tprop in obj[embed][ext] and ts_re.match(obj[embed][ext][tprop]):
                                            try:
                                                parser.parse(obj[embed][ext][tprop])
                                            except ValueError as e:
                                                yield JSONError("'%s': '%s': '%s': '%s' is not a valid timestamp: %s"
                                                                % (obj['type'], ext, tprop, obj[embed][ext][tprop], str(e)), instance['id'])
                                elif tprop in obj[embed] and ts_re.match(obj[embed][tprop]):
                                    try:
                                        parser.parse(obj[embed][tprop])
                                    except ValueError as e:
                                        yield JSONError("'%s': '%s': '%s' is not a valid timestamp: %s"
                                                        % (obj['type'], tprop, obj[embed][tprop], str(e)), instance['id'])
        else:
            if 'type' not in instance:
                return
            if instance['type'] in enums.TIMESTAMP_OBSERVABLE_PROPERTIES:
                for tprop in enums.TIMESTAMP_OBSERVABLE_PROPERTIES[instance['type']]:
                    if tprop in instance and ts_re.match(instance[tprop]):
                        # Don't raise an error if schemas will catch it
                        try:
                            parser.parse(instance[tprop])
                        except ValueError as e:
                            yield JSONError("'%s': '%s': '%s' is not a valid timestamp: %s"
                                            % (instance['type'], tprop, instance[tprop], str(e)), instance['id'])
            if instance['type'] in enums.TIMESTAMP_EMBEDDED_PROPERTIES:
                for embed in enums.TIMESTAMP_EMBEDDED_PROPERTIES[instance['type']]:
                    if embed in instance and isinstance(instance[embed], collections.Mapping):
                        for tprop in enums.TIMESTAMP_EMBEDDED_PROPERTIES[instance['type']][embed]:
                            if embed == 'extensions':
                                for ext in instance[embed]:
                                    if tprop in instance[embed][ext] and ts_re.match(instance[embed][ext][tprop]):
                                        try:
                                            parser.parse(instance[embed][ext][tprop])
                                        except ValueError as e:
                                            yield JSONError("'%s': '%s': '%s': '%s' is not a valid timestamp: %s"
                                                            % (instance['type'], ext, tprop, instance[embed][ext][tprop], str(e)), instance['id'])
                            elif tprop in instance[embed] and ts_re.match(instance[embed][tprop]):
                                try:
                                    parser.parse(instance[embed][tprop])
                                except ValueError as e:
                                    yield JSONError("'%s': '%s': '%s' is not a valid timestamp: %s"
                                                    % (instance['type'], tprop, instance[embed][tprop], str(e)), instance['id'])


def get_comparison_string(op):
    """Return a string explaining the given comparison operator.
    """
    if op == 'gt':
        return 'later than'
    elif op == 'ge':
        return 'later than or equal to'
    else:
        raise ValueError('Unknown operator: {}'.format(op))


def timestamp_compare(instance):
    """Ensure timestamp properties with a comparison requirement are valid.

    E.g. `modified` must be later or equal to `created`.
    """
    compares = [('modified', 'ge', 'created')]
    additional_compares = enums.TIMESTAMP_COMPARE.get(instance.get('type', ''), [])
    compares.extend(additional_compares)

    for first, op, second in compares:
        comp = getattr(operator, op)
        comp_str = get_comparison_string(op)

        if first in instance and second in instance and \
                not comp(instance[first], instance[second]):
            msg = "'%s' (%s) must be %s '%s' (%s)"
            yield JSONError(msg % (first, instance[first], comp_str, second, instance[second]),
                            instance['id'])


@cyber_observable_check("2.1")
def observable_timestamp_compare(instance):
    """Ensure cyber observable timestamp properties with a comparison
    requirement are valid.
    """
    compares = enums.TIMESTAMP_COMPARE_OBSERVABLE.get(instance.get('type', ''), [])
    for first, op, second in compares:
        comp = getattr(operator, op)
        comp_str = get_comparison_string(op)

        if first in instance and second in instance and \
                not comp(instance[first], instance[second]):
            msg = "In object '%s', '%s' (%s) must be %s '%s' (%s)"
            yield JSONError(msg % (instance['id'], first, instance[first], comp_str, second, instance[second]),
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

    list_index_re = re.compile(r"\[(\d+)\]")
    for marking in instance['granular_markings']:
        if 'selectors' not in marking:
            continue

        selectors = marking['selectors']
        for selector in selectors:
            segments = selector.split('.')

            obj = instance
            prev_segmt = None
            for segmt in segments:
                index_match = list_index_re.match(segmt)
                if index_match:
                    try:
                        idx = int(index_match.group(1))
                        obj = obj[idx]
                    except IndexError:
                        yield JSONError("'%s' is not a valid selector because"
                                        " %s is not a valid index."
                                        % (selector, idx), instance['id'])
                    except KeyError:
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
                    except TypeError:
                        yield JSONError("'%s' is not a valid selector because"
                                        " '%s' is not a property."
                                        % (selector, segmt), instance['id'])
                prev_segmt = segmt


def check_observable_refs(refs, obj_prop, enum_prop, embed_obj_prop, enum_vals,
                          key, instance):
    if embed_obj_prop != '':
        embed_obj_prop = "'" + embed_obj_prop + "' "

    if not isinstance(refs, list):
        refs = [refs]
    for ref in refs:
        try:
            refed_obj = instance['objects'][ref]
        except KeyError:
            yield JSONError("%s in observable object '%s' can't "
                            "resolve %sreference '%s'."
                            % (obj_prop, key, embed_obj_prop, ref),
                            instance['id'])
            continue
        try:
            refed_type = refed_obj['type']
        except KeyError:
            continue
        if refed_type not in enum_vals:
            if len(enum_vals) == 1:
                valids = "'" + enum_vals[0] + "'"
            else:
                valids = "'%s or '%s'" % ("', '".join(enum_vals[:-1]),
                                          enum_vals[-1])
            yield JSONError("'%s' in observable object '%s' must "
                            "refer to an object of type %s."
                            % (obj_prop, key, valids), instance['id'])


@cyber_observable_check("2.1", True)
def observable_object_references(instance):
    """Ensure certain observable object properties reference the correct type
    of object.
    """
    if instance['type'] == 'observed-data':
        for key, obj in instance['objects'].items():
            for error in observable_object_references_helper(obj, key, instance):
                yield error


def observable_object_references_helper(obj, key, instance):
    if 'type' not in obj:
        return
    elif obj['type'] not in enums.OBSERVABLE_PROP_REFS:
        return

    obj_type = obj['type']
    for obj_prop in enums.OBSERVABLE_PROP_REFS[obj_type]:
        if obj_prop not in obj:
            continue
        enum_prop = enums.OBSERVABLE_PROP_REFS[obj_type][obj_prop]
        if isinstance(enum_prop, list):
            refs = obj[obj_prop]
            enum_vals = enum_prop
            for x in check_observable_refs(refs, obj_prop, enum_prop, '',
                                           enum_vals, key, instance):
                yield x

        elif isinstance(enum_prop, dict):
            for embedded_prop in enum_prop:
                if isinstance(obj[obj_prop], dict):
                    if embedded_prop not in obj[obj_prop]:
                        continue
                    embedded_obj = obj[obj_prop][embedded_prop]
                    for embed_obj_prop in embedded_obj:
                        if embed_obj_prop not in enum_prop[embedded_prop]:
                            continue
                        refs = embedded_obj[embed_obj_prop]
                        enum_vals = enum_prop[embedded_prop][embed_obj_prop]
                        for x in check_observable_refs(refs, obj_prop, enum_prop,
                                                       embed_obj_prop, enum_vals,
                                                       key, instance):
                            yield x

                elif isinstance(obj[obj_prop], list):
                    for embedded_list_obj in obj[obj_prop]:

                        if embedded_prop not in embedded_list_obj:
                            continue
                        embedded_obj = embedded_list_obj[embedded_prop]
                        refs = embedded_obj
                        enum_vals = enum_prop[embedded_prop]
                        for x in check_observable_refs(refs, obj_prop, enum_prop,
                                                       embedded_prop, enum_vals,
                                                       key, instance):
                            yield x


@cyber_observable_check("2.1")
def artifact_mime_type(instance):
    """Ensure the 'mime_type' property of artifact objects comes from the
    Template column in the IANA media type registry.
    """
    if ('type' in instance and instance['type'] == 'artifact' and 'mime_type' in instance):
        if enums.media_types():
            if instance['mime_type'] not in enums.media_types():
                yield JSONError("The 'mime_type' property of object '%s' "
                                "('%s') must be an IANA registered MIME "
                                "Type of the form 'type/subtype'."
                                % (instance['id'], instance['mime_type']), instance['id'])

        else:
            info("Can't reach IANA website; using regex for mime types.")
            mime_re = re.compile(r'^(application|audio|font|image|message|model'
                                 '|multipart|text|video)/[a-zA-Z0-9.+_-]+')
            if not mime_re.match(instance['mime_type']):
                yield JSONError("The 'mime_type' property of object '%s' "
                                "('%s') should be an IANA MIME Type of the"
                                " form 'type/subtype'."
                                % (instance['id'], instance['mime_type']), instance['id'])


@cyber_observable_check("2.1")
def character_set(obj):
    """Ensure certain properties of cyber observable objects come from the IANA
    Character Set list.
    """
    key = obj['id']
    char_re = re.compile(r'^[a-zA-Z0-9_\(\)-]+$')
    if ('type' in obj and obj['type'] == 'directory' and 'path_enc' in obj):
        if enums.char_sets():
            if obj['path_enc'] not in enums.char_sets():
                yield JSONError("The 'path_enc' property of object '%s' "
                                "('%s') must be an IANA registered "
                                "character set."
                                % (key, obj['path_enc']), obj['id'])
        else:
            info("Can't reach IANA website; using regex for character_set.")
            if not char_re.match(obj['path_enc']):
                yield JSONError("The 'path_enc' property of object '%s' "
                                "('%s') must be an IANA registered "
                                "character set."
                                % (key, obj['path_enc']), obj['id'])

    if ('type' in obj and obj['type'] == 'file' and 'name_enc' in obj):
        if enums.char_sets():
            if obj['name_enc'] not in enums.char_sets():
                yield JSONError("The 'name_enc' property of object '%s' "
                                "('%s') must be an IANA registered "
                                "character set."
                                % (key, obj['name_enc']), obj['id'])
        else:
            info("Can't reach IANA website; using regex for character_set.")
            if not char_re.match(obj['name_enc']):
                yield JSONError("The 'name_enc' property of object '%s' "
                                "('%s') must be an IANA registered "
                                "character set." % (key, obj['name_enc']), obj['id'])


def language(instance):
    """Ensure the 'lang' property of SDOs is a valid RFC 5646 language code.
    """
    if ('lang' in instance and instance['lang'] not in enums.LANG_CODES):
        yield JSONError("'%s' is not a valid RFC 5646 language code."
                        % instance['lang'], instance['id'])


@cyber_observable_check("2.1")
def software_language(instance):
    """Ensure the 'language' property of software objects is a valid ISO 639-2
    language code.
    """
    if ('type' in instance and instance['type'] == 'software' and
            'languages' in instance):
        for lang in instance['languages']:
            if lang not in enums.SOFTWARE_LANG_CODES:
                yield JSONError("The 'languages' property of object '%s' "
                                "contains an invalid ISO 639-2 language "
                                " code ('%s')."
                                % (instance['id'], lang), instance['id'])


def patterns(instance, options):
    """Ensure that the syntax of the pattern of an indicator is valid, and that
    objects and properties referenced by the pattern are valid.
    """
    if (instance['type'] != 'indicator' or instance.get('pattern_type', '') != 'stix' or
            isinstance(instance.get('pattern', ''), string_types) is False):
        return

    pattern = instance['pattern']
    if 'pattern_version' in instance:
        pattern_version = instance['pattern_version']
    elif 'spec_version' in instance:
        pattern_version = instance['spec_version']
    else:
        pattern_version = '2.1'
    errors = pattern_validator(pattern, pattern_version)

    # Check pattern syntax
    if errors:
        for e in errors:
            yield PatternError(str(e), instance['id'])
        return

    p = Pattern(pattern)
    inspection = p.inspect().comparisons
    for objtype in inspection:
        # Check observable object types
        if objtype in enums.OBSERVABLE_TYPES:
            pass
        elif (not TYPE_FORMAT_RE.match(objtype) or
              len(objtype) < 3 or len(objtype) > 250):
            yield PatternError("'%s' is not a valid observable type name"
                               % objtype, instance['id'])
        elif (all(x not in options.disabled for x in ['all', 'format-checks', 'custom-prefix']) and
              not CUSTOM_TYPE_PREFIX_RE.match(objtype)):
            yield PatternError("Custom Observable Object type '%s' should start "
                               "with 'x-' followed by a source unique identifier "
                               "(like a domain name with dots replaced by "
                               "hyphens), a hyphen and then the name"
                               % objtype, instance['id'])
        elif (all(x not in options.disabled for x in ['all', 'format-checks', 'custom-prefix-lax']) and
              not CUSTOM_TYPE_LAX_PREFIX_RE.match(objtype)):
            yield PatternError("Custom Observable Object type '%s' should start "
                               "with 'x-'" % objtype, instance['id'])

        # Check observable object properties
        expression_list = inspection[objtype]
        for exp in expression_list:
            path = exp[0]
            # Get the property name without list index, dictionary key, or referenced object property
            prop = path[0]
            if objtype in enums.OBSERVABLE_PROPERTIES and prop in enums.OBSERVABLE_PROPERTIES[objtype]:
                continue
            elif not PROPERTY_FORMAT_RE.match(prop):
                yield PatternError("'%s' is not a valid observable property name"
                                   % prop, instance['id'])
            elif objtype not in enums.OBSERVABLE_TYPES:
                continue  # custom SCOs aren't required to use x_ prefix on properties
            elif (all(x not in options.disabled for x in ['all', 'format-checks', 'custom-prefix']) and
                  not CUSTOM_PROPERTY_PREFIX_RE.match(prop)):
                yield PatternError("Cyber Observable Object custom property '%s' "
                                   "should start with 'x_' followed by a source "
                                   "unique identifier (like a domain name with "
                                   "dots replaced by underscores), an "
                                   "underscore and then the name"
                                   % prop, instance['id'])
            elif (all(x not in options.disabled for x in ['all', 'format-checks', 'custom-prefix-lax']) and
                  not CUSTOM_PROPERTY_LAX_PREFIX_RE.match(prop)):
                yield PatternError("Cyber Observable Object custom property '%s' "
                                   "should start with 'x_'" % prop, instance['id'])


def cpe_check(instance):
    """Checks to see if provided cpe is a valid CPE v2.3 entry
    """
    if 'cpe' not in instance:
        return
    try:
        CPE(instance['cpe'], CPE.VERSION_2_3)
    except NotImplementedError:
        yield JSONError(
                "Provided CPE value '%s' is not CPE v2.3 compliant." %
                instance['cpe'], instance['id'],
        )


def language_contents(instance):
    """Ensure keys in Language Content's 'contents' dictionary are valid
    language codes, and that the keys in the sub-dictionaries match the rules
    for object property names.
    """
    if instance['type'] != 'language-content' or 'contents' not in instance:
        return

    for key, value in instance['contents'].items():
        if key not in enums.LANG_CODES:
            yield JSONError("Invalid key '%s' in 'contents' property must be"
                            " an RFC 5646 code" % key, instance['id'])
        for subkey, subvalue in value.items():
            if not PROPERTY_FORMAT_RE.match(subkey):
                yield JSONError("'%s' in '%s' of the 'contents' property is "
                                "invalid and must match a valid property name"
                                % (subkey, key), instance['id'])


def uuid_version_check(instance):
    """Ensure that an SCO with only optional ID Contributing Properties use a
    UUIDv4"""
    x = ['artifact', 'email-message', 'user-account', 'windows-registry-key', 'x509-certificate']
    if instance['type'] not in x or 'id' not in instance:
        return

    object_id = uuid.UUID(instance['id'].split("--")[-1])
    if instance['type'] == 'artifact':
        x = ['hashes', 'payload_bin']
    elif instance['type'] == 'email-message':
        x = ['from_ref', 'subject', 'body']
    elif instance['type'] == 'user-account':
        x = ['account_type', 'user_id', 'account_login']
    elif instance['type'] == 'windows-registry-key':
        x = ['key', 'values']
    elif instance['type'] == 'x509-certificate':
        x = ['hashes', 'serial_number']

    if all(k not in instance for k in x) and object_id.version != 4:
        yield JSONError("If no Contributing Properties are present, a UUIDv4 "
                        "must be used", instance['id'])


def process(instance):
    """Ensure that process objects use UUIDv4"""
    if instance['type'] != 'process':
        return

    object_id = uuid.UUID(instance['id'].split("--")[-1])
    if object_id.version != 4:
        yield JSONError("A process object must use UUIDv4 for its id", instance['id'])


def list_musts(options):
    """Construct the list of 'MUST' validators to be run by the validator.
    """
    validator_list = [
        timestamp,
        timestamp_compare,
        observable_timestamp_compare,
        object_marking_circular_refs,
        granular_markings_circular_refs,
        marking_selector_syntax,
        observable_object_references,
        artifact_mime_type,
        character_set,
        language,
        software_language,
        patterns,
        cpe_check,
        language_contents,
        uuid_version_check,
        process,
    ]

    return validator_list
