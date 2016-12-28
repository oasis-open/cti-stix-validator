"""Mandatory (MUST) requirement checking functions
"""

import re
from . import enums
from .util import cyber_observable_check
from .errors import JSONError


def modified_created(instance):
    """`modified` property must be later or equal to `created` property
    """
    if 'modified' in instance and 'created' in instance and \
            instance['modified'] < instance['created']:
        msg = "'modified' (%s) must be later or equal to 'created' (%s)"
        return JSONError(msg % (instance['modified'], instance['created']),
                         instance['id'])


def version(instance):
    """Check constraints on 'version' property
    """
    if 'version' in instance and 'modified' in instance and \
            'created' in instance:
        if instance['version'] == 1 and instance['modified'] != instance['created']:
            msg = "'version' is 1, but 'created' (%s) is not equal to 'modified' (%s)"
            return JSONError(msg % (instance['created'], instance['modified']),
                             instance['id'])
        elif instance['version'] > 1 and instance['modified'] <= instance['created']:
            msg = "'version' is greater than 1, but 'modified' (%s) is not greater than 'created' (%s)"
            return JSONError(msg % (instance['modified'], instance['created']),
                             instance['id'])


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


def types_strict(instance):
    """Ensure that no custom object types are used, but only the official ones
    from the specification.
    """
    if instance['type'] not in enums.TYPES:
        return JSONError("Object type '%s' is not one of those detailed in the"
                         " specification." % instance['type'], instance['id'])


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
                if not isinstance(refs, list):
                    refs = [refs]
                for ref in refs:
                    try:
                        refed_obj = instance['objects'][ref]
                    except KeyError:
                        yield JSONError("%s in observable object '%s' can't "
                                        "resolve reference '%s'."
                                        % (obj_prop, key, ref), instance['id'])
                        continue
                    try:
                        refed_type = refed_obj['type']
                    except KeyError:
                        continue
                    enum_vals = enum_prop
                    if refed_type not in enum_vals:
                        if len(enum_vals) == 1:
                            valids = "'" + enum_vals[0] + "'"
                        else:
                            valids = "'%s or '%s'" % ("', '".join(enum_vals[:-1]),
                                                      enum_vals[-1])
                        yield JSONError("'%s' in observable object '%s' must "
                                        "refer to an object of type %s."
                                        % (obj_prop, key, valids), instance['id'])
            elif isinstance(enum_prop, dict):
                for embedded_prop in enum_prop:
                    if embedded_prop not in obj[obj_prop]:
                        continue
                    embedded_obj = obj[obj_prop][embedded_prop]
                    for embed_obj_prop in embedded_obj:
                        if embed_obj_prop not in enum_prop[embedded_prop]:
                            continue
                        refs = embedded_obj[embed_obj_prop]
                        if not isinstance(refs, list):
                            refs = [refs]
                        for ref in refs:
                            try:
                                refed_obj = instance['objects'][ref]
                            except KeyError:
                                yield JSONError("%s in observable object '%s' "
                                                "can't resolve '%s' reference "
                                                "'%s'."
                                                % (obj_prop, key, embed_obj_prop, ref),
                                                instance['id'])
                                continue
                            try:
                                refed_type = refed_obj['type']
                            except KeyError:
                                continue
                            enum_vals = enum_prop[embedded_prop][embed_obj_prop]
                            if refed_type not in enum_vals:
                                if len(enum_vals) == 1:
                                    valids = "'" + enum_vals[0] + "'"
                                else:
                                    valids = "'%s or '%s'" % ("', '".join(enum_vals[:-1]),
                                                              enum_vals[-1])
                                yield JSONError("'%s' in observable object '%s' must "
                                                "refer to an object of type %s."
                                                % (obj_prop, key, valids), instance['id'])


def list_musts(options):
    """Construct the list of 'MUST' validators to be run by the validator.
    """
    validator_list = [
        modified_created,
        version,
        timestamp_precision,
        object_marking_circular_refs,
        granular_markings_circular_refs,
        marking_selector_syntax,
        observable_object_references
    ]

    # --strict-types
    if options.strict_types:
        validator_list.append(types_strict)

    return validator_list
