#!/usr/bin/env python

"""Validate STIX 2.0 documents against the specification.
"""


import logging
import argparse
import sys
import textwrap
from argparse import RawDescriptionHelpFormatter
from stix2validator import (codes, output, ValidationOptions, run_validation,
                            print_results, ValidationError)

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
| 141  | observable-object-keys      | observable object keys follow the      |
|      |                             | correct format                         |
| 142  | observable-dictionary-keys  | dictionaries in cyber observable       |
|      |                             | objects follow the correct format      |
| 143  | custom-observable-object-   | custom observable object names follow  |
|      |     prefix                  | the correct format                     |
| 144  | custom-observable-object-   | same as 144 but more lenient; no       |
|      |     prefix-lax              | source identifier needed in prefix     |
| 145  | custom-object-extension-    | custom observable object extension     |
|      |     prefix                  | names follow the correct format        |
| 146  | custom-object-extension-    | same as 145 but more lenient; no       |
|      |     prefix-lax              | source identifier needed in prefix     |
| 147  | custom-observable-          | observable object custom property      |
|      |     properties-prefix       | names follow the correct format        |
| 148  | custom-observable-          | same as 148 but more lenient; no       |
|      |     properties-prefix-lax   | source identifier needed in prefix     |
| 149  | windows-process-priority-   | windows-process-ext's 'priority'       |
|      |     format                  | follows the correct format             |
|      |                             |                                        |
|  2   | approved-values             | all 2xx checks are run                 |
| 201  | marking-definition-type     | marking definitions use a valid        |
|      |                             | definition_type                        |
| 202  | relationship-types          | relationships are among those defined  |
|      |                             | in the specification                   |
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
| 241  | hash-algo                   | certain property values are from the   |
|      |                             | hash-algo vocabulary                   |
| 242  | encryption-algo             | certain property values are from the   |
|      |                             | encryption-algo vocabulary             |
| 243  | windows-pebinary-type       | certain property values are from the   |
|      |                             | windows-pebinary-type vocabulary       |
| 244  | account-type                | certain property values are from the   |
|      |                             | account-type vocabulary                |
| 270  | all-external-sources        | all of the following external source   |
|      |                             | checks are run                         |
| 271  | mime-type                   | file.mime_type is a valid IANA MIME    |
|      |                             | type                                   |
| 272  | protocols                   | certain property values are valid IANA |
|      |                             | Service and Protocol names             |
| 273  | ipfix                       | certain property values are valid IANA |
|      |                             | IP Flow Information Export (IPFIX)     |
|      |                             | Entities                               |
| 274  | http-request-headers        | certain property values are valid HTTP |
|      |                             | request header names                   |
| 275  | socket-options              | certain property values are valid      |
|      |                             | socket options                         |
| 276  | pdf-doc-info                | certain property values are valid PDF  |
|      |                             | Document Information Dictionary keys   |
| 301  | network-traffic-ports       | network-traffic objects contain both   |
|      |                             | src_port and dst_port                  |
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
        default=True,
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
        dest="disabled",
        default="",
        help="A comma-separated list of recommended best practice checks to "
             "skip. By default, no checks are disabled. \n\n"
             "Example: --disable 212,220"
    )

    parser.add_argument(
        "-e",
        "--enable",
        "--select",
        dest="enabled",
        default="",
        help="A comma-separated list of recommended best practice checks to "
             "enable. If the --disable option is not used, no other checks "
             "will be run. By default, all checks are enabled.\n\n"
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

    parser.add_argument(
        "--no-cache",
        dest="no_cache",
        action="store_true",
        default=False,
        help="Disable the caching of external source values."
    )

    parser.add_argument(
        "--refresh-cache",
        dest="refresh_cache",
        action="store_true",
        default=False,
        help="Clears the cache of external source values, then "
             "during validation downloads them again."
    )

    parser.add_argument(
        "--clear-cache",
        dest="clear_cache",
        action="store_true",
        default=False,
        help="Clear the cache of external source values after validation."
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
