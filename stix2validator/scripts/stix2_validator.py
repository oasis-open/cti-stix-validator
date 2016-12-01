#!/usr/bin/env python

"""Validate STIX 2.0 documents against the specification.
"""


import logging
import argparse
import sys
import textwrap
from argparse import RawDescriptionHelpFormatter
from stix2validator import *
from stix2validator import codes
from stix2validator.validators import ValidationOptions


CODES_TABLE = """
The following is a table of all the recommended "best practice" checks which
the validator performs, along with the code to use with the --enable or
--disable options. By default, the validator checks all of them.

+------+-----------------------------+----------------------------------------+
| Code | Name                        | Ensures...                             |
+------+-----------------------------+----------------------------------------+
|  1   | format-checks               | all 1xx checks are run                 |
| 101  | custom-object-prefix        | custom object type names follow the    |
|      |                             | correct format                         |
| 102  | custom-object-prefix-lax    | same as 101 but more lenient; no       |
|      |                             | source identifier needed in prefix     |
| 103  | custom-property-prefix      | custom object property names follow    |
|      |                             | the correct format                     |
| 104  | custom-property-prefix-lax  | same as 103 but more lenient; no       |
|      |                             | source identifier needed in prefix     |
| 111  | open-vocab-format           | values of open vocabularies follow the |
|      |                             | correct format                         |
| 121  | kill-chain-names            | kill-chain-phase name and phase follow |
|      |                             | the correct format                     |
|      |                             |                                        |
|  2   | approved-values             | all 2xx checks are run                 |
| 210  | all-vocabs                  | all of the following open vocabulary   |
|      |                             | checks are run                         |
| 211  | attack-motivation           | certain property values are from the   |
|      |                             | attack_motivation vocabulary           |
| 212  | attack-resource-level       | certain property values are from the   |
|      |                             | attack_resource_level vocabulary       |
| 213  | identity-class              | certain property values are from the   |
|      |                             | identity_class vocabulary              |
| 214  | indicator-label             | certain property values are from the   |
|      |                             | indicator_label vocabulary             |
| 215  | industry-sector             | certain property values are from the   |
|      |                             | industry_sector vocabulary             |
| 216  | malware-label               | certain property values are from the   |
|      |                             | malware_label vocabulary               |
| 217  | pattern-lang                | certain property values are from the   |
|      |                             | pattern_lang vocabulary                |
| 218  | report-label                | certain property values are from the   |
|      |                             | report_label vocabulary                |
| 219  | threat-actor-label          | certain property values are from the   |
|      |                             | threat_actor_label vocabulary          |
| 220  | threat-actor-role           | certain property values are from the   |
|      |                             | threat_actor_role vocabulary           |
| 221  | threat-actor-sophistication | certain property values are from the   |
|      |                             | threat_actor_sophistication vocabulary |
| 222  | tool-label                  | certain property values are from the   |
|      |                             | tool_label vocabulary                  |
| 229  | marking-definition-type     | marking definitions use a valid        |
|      |                             | definition_type                        |
| 250  | relationship-types          | relationships are among those defined  |
|      |                             | in the specification                   |
+------+-----------------------------+----------------------------------------+
"""


class NewlinesHelpFormatter(RawDescriptionHelpFormatter):
    """Custom help formatter to insert newlines between argument help texts.
    """
    def _split_lines(self, text, width):
        text = self._whitespace_matcher.sub(' ', text).strip()
        txt = textwrap.wrap(text, width)
        txt[-1] += '\n'
        return txt


def _get_arg_parser(is_script=True):
    """Initializes and returns an argparse.ArgumentParser instance for this
    application.

    Args:
        is_script: Whether the arguments are intended for use in a stand-alone
            script or imported into another tool.

    Returns:
        Instance of ``argparse.ArgumentParser``

    """
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=NewlinesHelpFormatter,
        epilog=CODES_TABLE
    )

    # Input options
    if is_script:
        parser.add_argument(
            "files",
            metavar="FILES",
            nargs="+",
            help="A whitespace separated list of STIX files or directories of "
                 "STIX files to validate."
        )
    parser.add_argument(
        "-r",
        "--recursive",
        dest="recursive",
        action="store_true",
        default=False,
        help="Recursively descend into input directories."
    )
    parser.add_argument(
        "-s",
        "--schemas",
        dest="schema_dir",
        help="Schema directory. If not provided, the STIX schemas bundled "
             "with this script will be used."
    )

    # Output options
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        action="store_true",
        default=False,
        help="Print informational notes and more verbose error messages."
    )

    parser.add_argument(
        "-d",
        "--disable",
        "--ignore",
        dest="ignored",
        default="",
        help="A comma-separated list of recommended best practice checks to "
            "skip. By default, no checks are disabled. \n\n"
            "Example: --ignore 212,220"
    )

    parser.add_argument(
        "-e",
        "--enable",
        "--select",
        dest="enabled",
        default="",
        help="A comma-separated list of recommended best practice checks to "
            "enable. If the --disable option is not used, no other checks will"
            " be run. By default, all checks are enabled.\n\n"
            "Example: --enable 250"
    )

    parser.add_argument(
        "--strict",
        dest="strict",
        action="store_true",
        default=False,
        help="Treat warnings as errors and fail validation if any are found."
    )

    parser.add_argument(
        "--strict-types",
        dest="strict_types",
        action="store_true",
        default=False,
        help="Ensure that no custom object types are used, only those detailed"
             " in the STIX specification."
    )

    return parser


def main():
    # Parse command line arguments
    parser = _get_arg_parser()
    args = parser.parse_args()

    options = ValidationOptions(args)

    try:
        # Set the output level (e.g., quiet vs. verbose)
        output.set_level(options.verbose)

        # Validate input documents
        results = run_validation(options)

        # Print validation results
        print_results(results)

        # Determine exit status code and exit.
        code = codes.get_code(results)
        sys.exit(code)

    except (ValidationError, IOError) as ex:
        output.error(
            "Validation error occurred: '%s'" % str(ex),
            codes.EXIT_VALIDATION_ERROR
        )
    except Exception:
        logging.exception("Fatal error occurred")
        sys.exit(codes.EXIT_FAILURE)

if __name__ == '__main__':
    main()
