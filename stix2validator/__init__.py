# Expose certain functions and classes to the stix2validator namespace
# flake8: noqa

import logging
import sys

from .errors import ValidationError
from .output import print_results
from .util import ValidationOptions, parse_args
from .validator import (run_validation, validate, validate_file,
                        validate_parsed_json, validate_string)
from .version import __version__

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='%(message)s')
