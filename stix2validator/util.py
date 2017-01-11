import os
from collections import Iterable


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
        no_cache: Specifies that caching of values from external sources should
            be disabled.
        refresh_cache: Specifies that the cache of values from external sources
            should be cleared before validation, and then re-downloaded during
            validation.
        clear_cache: Specifies that the cache of values from external sources
            should be cleared after validation.

    """
    def __init__(self, cmd_args=None, verbose=False, files=None,
                 recursive=False, schema_dir=None, disabled="",
                 enabled="", strict=False, strict_types=False,
                 no_cache=False, refresh_cache=False, clear_cache=False):
        if cmd_args is not None:
            self.verbose = cmd_args.verbose
            self.files = cmd_args.files
            self.recursive = cmd_args.recursive
            self.schema_dir = cmd_args.schema_dir
            self.disabled = cmd_args.disabled
            self.enabled = cmd_args.enabled
            self.strict = cmd_args.strict
            self.strict_types = cmd_args.strict_types
            self.no_cache = cmd_args.no_cache
            self.refresh_cache = cmd_args.refresh_cache
            self.clear_cache = cmd_args.clear_cache
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

            # cache options
            self.no_cache = no_cache
            self.refresh_cache = refresh_cache
            self.clear_cache = clear_cache

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


# Mapping of check code numbers to names
CHECK_CODES = {
    '1': 'format-checks',
    '101': 'custom-object-prefix',
    '102': 'custom-object-prefix-lax',
    '103': 'custom-property-prefix',
    '104': 'custom-property-prefix-lax',
    '111': 'open-vocab-format',
    '121': 'kill-chain-names',
    '141': 'observable-object-keys',
    '142': 'observable-dictionary-keys',
    '143': 'custom-observable-object-prefix',
    '144': 'custom-observable-object-prefix-lax',
    '145': 'custom-object-extension-prefix',
    '146': 'custom-object-extension-prefix-lax',
    '147': 'custom-observable-properties-prefix',
    '148': 'custom-observable-properties-prefix-lax',
    '149': 'windows-process-priority-format',
    '2': 'approved-values',
    '201': 'marking-definition-type',
    '202': 'relationship-types',
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
    '241': 'hash-algo',
    '242': 'encryption-algo',
    '243': 'windows-pebinary-type',
    '244': 'account-type',
    '270': 'all-external-sources',
    '271': 'mime-type',
    '272': 'protocols',
    '273': 'ipfix',
    '274': 'http-request-headers',
    '275': 'socket-options',
    '276': 'pdf-doc-info',
    '301': 'network-traffic-ports'
}


def has_cyber_observable_data(instance):
    """Return True only if the given instance is an observed-data object
    containing STIX Cyber Observable objects.
    """
    if (instance['type'] == 'observed-data' and
            'objects' in instance and
            type(instance['objects']) is dict):
        return True
    return False


def cyber_observable_check(original_function):
    """Decorator for functions that require cyber observable data.
    """
    def new_function(*args, **kwargs):
        if not has_cyber_observable_data(args[0]):
            return
        func = original_function(*args, **kwargs)
        if isinstance(func, Iterable):
            for x in original_function(*args, **kwargs):
                yield x
    new_function.__name__ = original_function.__name__
    return new_function
