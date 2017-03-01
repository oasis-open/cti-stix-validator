"""Mandatory (MUST) requirement checking functions
"""

import re
from stix2patterns.validator import run_validator as pattern_validator
from . import enums
from .util import cyber_observable_check, has_cyber_observable_data
from .errors import JSONError
from .output import info


def modified_created(instance):
    """`modified` property must be later or equal to `created` property
    """
    if 'modified' in instance and 'created' in instance and \
            instance['modified'] < instance['created']:
        msg = "'modified' (%s) must be later or equal to 'created' (%s)"
        return JSONError(msg % (instance['modified'], instance['created']),
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


@cyber_observable_check
def observable_object_references(instance):
    """Ensure certain observable object properties reference the correct type
    of object.
    """
    for key, obj in instance['objects'].items():
        if 'type' not in obj:
            continue
        elif obj['type'] not in enums.OBSERVABLE_PROP_REFS:
            continue

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


@cyber_observable_check
def artifact_mime_type(instance):
    """Ensure the 'mime_type' property of artifact objects comes from the
    Template column in the IANA media type registry.
    """
    for key, obj in instance['objects'].items():
        if ('type' in obj and obj['type'] == 'artifact' and 'mime_type' in obj):
            if enums.media_types():
                if obj['mime_type'] not in enums.media_types():
                    yield JSONError("The 'mime_type' property of object '%s' "
                                    "('%s') must be an IANA registered MIME "
                                    "Type of the form 'type/subtype'."
                                    % (key, obj['mime_type']), instance['id'])

            else:
                info("Can't reach IANA website; using regex for mime types.")
                mime_pattern = '^(application|audio|font|image|message|model' \
                               '|multipart|text|video)/[a-zA-Z0-9.+_-]+'
                if not re.match(mime_pattern, obj['mime_type']):
                    yield JSONError("The 'mime_type' property of object '%s' "
                                    "('%s') should be an IANA MIME Type of the"
                                    " form 'type/subtype'."
                                    % (key, obj['mime_type']), instance['id'])


@cyber_observable_check
def character_set(instance):
    """Ensure certain properties of cyber observable objects come from the IANA
    Character Set list.
    """
    for key, obj in instance['objects'].items():
        if ('type' in obj and obj['type'] == 'directory' and 'path_enc' in obj):
            if enums.char_sets():
                if obj['path_enc'] not in enums.char_sets():
                    yield JSONError("The 'path_enc' property of object '%s' "
                                    "('%s') must be an IANA registered "
                                    "character set."
                                    % (key, obj['path_enc']), instance['id'])
            else:
                info("Can't reach IANA website; using regex for character_set.")
                char_pattern = '^[a-zA-Z0-9_\(\)-]+$'
                if not re.match(char_pattern, obj['path_enc']):
                    yield JSONError("The 'path_enc' property of object '%s' "
                                    "('%s') must be an IANA registered "
                                    "character set."
                                    % (key, obj['path_enc']), instance['id'])

        if ('type' in obj and obj['type'] == 'file' and 'name_enc' in obj):
            if enums.char_sets():
                if obj['name_enc'] not in enums.char_sets():
                    yield JSONError("The 'name_enc' property of object '%s' "
                                    "('%s') must be an IANA registered "
                                    "character set."
                                    % (key, obj['name_enc']), instance['id'])
            else:
                info("Can't reach IANA website; using regex for character_set.")
                char_pattern = '^[a-zA-Z0-9_\(\)-]+$'
                if not re.match(char_pattern, obj['name_enc']):
                    yield JSONError("The 'name_enc' property of object '%s' "
                                    "('%s') must be an IANA registered "
                                    "character set."
                                    % (key, obj['name_enc']), instance['id'])


@cyber_observable_check
def software_language(instance):
    """Ensure the 'language' property of software objects is a valid ISO 639-2
    language code.
    """
    for key, obj in instance['objects'].items():
        if ('type' in obj and obj['type'] == 'software' and
                'languages' in obj):
            for lang in obj['languages']:
                if lang not in enums.LANG_CODES:
                    yield JSONError("The 'languages' property of object '%s' "
                                    "contains an invalid ISO 639-2 language "
                                    " code ('%s')."
                                    % (key, lang), instance['id'])


def types_strict(instance):
    """Ensure that no custom object types are used, but only the official ones
    from the specification.
    """
    if instance['type'] not in enums.TYPES:
        yield JSONError("Object type '%s' is not one of those detailed in the"
                        " specification." % instance['type'], instance['id'])
    elif has_cyber_observable_data(instance):
        for key, obj in instance['objects'].items():
            if 'type' in obj and obj['type'] not in enums.OBSERVABLE_TYPES:
                yield JSONError("Observable object %s is type '%s' which is "
                                "not one of those detailed in the "
                                "specification."
                                % (key, obj['type']), instance['id'])


def patterns(instance):
    """Ensure that the syntax of the pattern of an indicator is valid.
    """
    if instance['type'] != 'indicator' or 'pattern' not in instance:
        return

    pattern = instance['pattern']
    errors = pattern_validator(pattern)

    for e in errors:
        yield JSONError("Pattern failed to validate: %s."
                        % e, instance['id'])


def list_musts(options):
    """Construct the list of 'MUST' validators to be run by the validator.
    """
    validator_list = [
        modified_created,
        object_marking_circular_refs,
        granular_markings_circular_refs,
        marking_selector_syntax,
        observable_object_references,
        artifact_mime_type,
        character_set,
        software_language,
        patterns
    ]

    # --strict-types
    if options.strict_types:
        validator_list.append(types_strict)

    return validator_list
