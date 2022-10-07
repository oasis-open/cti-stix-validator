from .errors import JSONError


def interop_created_by_ref(instance):
    """Ensures that all SDOs reference a Producer"""
    if instance['type'] != 'bundle' or 'objects' not in instance:
        return

    rel_references = set()
    bad_references = set()

    """Find and store all producer ids and general identity ids
    use the bad references to inform on nature of error"""
    for obj in instance['objects']:
        if obj['type'] == 'identity':
            if 'created_by_ref' in obj:
                rel_references.add(obj['id'])
            else:
                bad_references.add(obj['id'])

    """Check if id is present in producers or normal identity SDOs"""
    for obj in instance['objects']:
        if obj['type'] != 'identity':
            if 'created_by_ref' not in obj:
                yield JSONError("created_by_ref is not present in Object", obj['id'])
            else:
                if obj['created_by_ref'] in bad_references:
                    yield JSONError("references %s as a producer "
                                    "but the identity is missing the property created_by_ref"
                                    % (obj['created_by_ref']), obj['id'])
                elif obj['created_by_ref'] not in rel_references:
                    yield JSONError("created_by_ref has value %s "
                                    "which is not found in bundle"
                                    % (obj['created_by_ref']), obj['id'])
