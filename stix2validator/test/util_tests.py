from .. import parse_args, validate_string
from .indicator_tests import VALID_INDICATOR


def test_parse_args():
    args = [
        '-r',
        '-s',
        '/tmp/schemas/',
        '-q',
        '-d',
        'format-checks',
        '-e',
        'custom-prefix',
        '--strict',
        '--strict-types',
        '--strict-properties',
        '--no-cache',
        '--refresh-cache',
        '--clear-cache',
        '/tmp/mystix.json',
    ]
    options = parse_args(args, True)

    assert options.verbose is False
    assert options.silent is True
    assert options.files == ['/tmp/mystix.json']
    assert options.recursive is True
    assert options.schema_dir == '/tmp/schemas/'
    assert options.disabled == ['format-checks']
    assert options.enabled == ['custom-prefix']
    assert options.strict is True
    assert options.strict_types is True
    assert options.strict_properties is True
    assert options.no_cache is True
    assert options.refresh_cache is True
    assert options.clear_cache is True


def test_parse_args_no_files():
    args = []
    options = parse_args(args)
    assert options.files == ""

    results = validate_string(VALID_INDICATOR, options)
    assert results.is_valid
