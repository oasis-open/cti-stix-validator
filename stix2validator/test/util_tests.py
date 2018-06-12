from .. import parse_args

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

    assert options.verbose == False
    assert options.silent == True
    assert options.files == ['/tmp/mystix.json']
    assert options.recursive == True
    assert options.schema_dir == '/tmp/schemas/'
    assert options.disabled == ['format-checks']
    assert options.enabled == ['custom-prefix']
    assert options.strict == True
    assert options.strict_types == True
    assert options.strict_properties == True
    assert options.no_cache == True
    assert options.refresh_cache == True
    assert options.clear_cache == True
