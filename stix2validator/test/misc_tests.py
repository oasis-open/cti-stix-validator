import os
import sys

import pytest

from . import ValidatorTest
from .. import ValidationOptions, run_validation
from .tool_tests import VALID_TOOL


class MiscTestCases(ValidatorTest):

    def test_run_validation(self):
        inputfile = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                 '..', 'schemas', 'examples',
                                 'using-granular-markings.json')
        options = ValidationOptions(files=[inputfile])
        results = run_validation(options)
        assert results[0].is_valid

    def test_run_validation_nonexistent_file(self):
        options = ValidationOptions(files='asdf.json')
        with pytest.raises(SystemExit):
            run_validation(options)


def test_run_validation_stdin(monkeypatch):
    monkeypatch.setattr(sys.stdin, 'read', lambda: VALID_TOOL)
    options = ValidationOptions(files=sys.stdin)
    results = run_validation(options)
    assert results[0].is_valid
