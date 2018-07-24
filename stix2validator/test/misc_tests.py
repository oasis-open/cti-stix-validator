from io import open
import logging
import os
import re
import sys

import pytest

from .. import (ValidationOptions, print_results, run_validation,
                validate_file, validate_string)
from .tool_tests import VALID_TOOL

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


def test_run_validation(caplog):
    inputfile = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                             '..', 'schemas', 'examples',
                             'indicator-to-campaign-relationship.json')
    options = ValidationOptions(files=[inputfile])
    results = run_validation(options)
    assert results[0].is_valid

    print_results(results)
    assert 'STIX JSON: Valid' in caplog.text


def test_run_validation_nonexistent_file():
    options = ValidationOptions(files='asdf.json')
    with pytest.raises(SystemExit):
        run_validation(options)


def test_run_validation_silent(caplog):
    inputfile = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                             '..', 'schemas', 'examples',
                             'indicator-to-campaign-relationship.json')
    options = ValidationOptions(files=[inputfile], silent=True)
    results = run_validation(options)
    print_results(results)
    assert caplog.text == ''


def test_validate_file(caplog):
    inputfile = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                             '..', 'schemas', 'examples',
                             'indicator-to-campaign-relationship.json')
    results = validate_file(inputfile)
    assert results.is_valid

    print_results(results)
    assert 'STIX JSON: Valid' in caplog.text


def test_validate_file_warning(caplog):
    inputfile = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                             'test_examples', 'identity_custom.json')
    results = validate_file(inputfile)
    assert results.is_valid

    print_results(results)
    assert re.search("Custom property .+ should have a type that starts with 'x_'", caplog.text)


def test_validate_file_invalid_brace(caplog):
    inputfile = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                             'test_examples', 'invalid_braces.json')
    results = validate_file(inputfile)
    assert not results.is_valid

    print_results(results)
    assert 'Fatal Error: Invalid JSON input' in caplog.text


def test_validate_file_invalid_comma(caplog):
    inputfile = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                             'test_examples', 'invalid_comma.json')
    results = validate_file(inputfile)
    assert not results.is_valid

    print_results(results)
    assert 'Fatal Error: Expecting property name' in caplog.text


def test_validate_file_invalid_missing_modified(caplog):
    inputfile = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                             'test_examples', 'invalid_identity.json')
    results = validate_file(inputfile)
    assert not results.is_valid

    print_results(results)
    assert "'modified' is a required property" in caplog.text


def test_validate_string(caplog):
    inputfile = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                             'test_examples', 'identity.json')
    with open(inputfile, encoding='utf-8') as f:
        results = validate_string(f.read())
    assert results.is_valid

    print_results(results)
    assert 'STIX JSON: Valid' in caplog.text


def test_validate_string_warning(caplog):
    inputfile = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                             'test_examples', 'identity_custom.json')
    with open(inputfile, encoding='utf-8') as f:
        results = validate_string(f.read())
    assert results.is_valid

    print_results(results)
    assert re.search("Custom property .+ should have a type that starts with 'x_'", caplog.text)


def test_validate_string_invalid_timestamp(caplog):
    inputfile = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                             'test_examples', 'invalid_timestamp.json')
    with open(inputfile, encoding='utf-8') as f:
        results = validate_string(f.read())
    assert not results.is_valid

    print_results(results)
    assert re.search("'modified' .+ must be later or equal to 'created'", caplog.text)


def test_print_results_invalid_parameter():
    with pytest.raises(ValueError) as excinfo:
        print_results('these results are valid')
    assert 'Argument to print_results() must be' in str(excinfo)


def test_run_validation_stdin(monkeypatch):
    monkeypatch.setattr(sys.stdin, 'read', lambda: VALID_TOOL)
    options = ValidationOptions(files=sys.stdin)
    results = run_validation(options)
    assert results[0].is_valid
