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
    return new_function
