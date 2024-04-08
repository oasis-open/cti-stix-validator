import copy
import json

from . import ValidatorTest
from ... import ValidationOptions, validate_parsed_json, validate_string

VALID_INDICATOR = u"""
{
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "created_by_ref": "source--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "created": "2016-04-06T20:03:48.000Z",
    "modified": "2016-04-06T20:03:48.000Z",
    "indicator_types": ["malicious-activity"],
    "name": "Poison Ivy Malware",
    "description": "This file is part of Poison Ivy",
    "pattern_type": "stix",
    "pattern": "[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']",
    "valid_from": "2016-04-06T20:03:48Z"
}
"""

ADDTNL_INVALID_SCHEMA = {
    "type": "x-foo-bar",
    "id": "x-type--353ed279-5f4f-4a79-bffc-b2e2ed08ea1f",
    "created": "2016-04-06T20:03:48.000Z",
    "modified": "2016-04-06T20:03:48.000Z",
}


class IndicatorTestCases(ValidatorTest):
    valid_indicator = json.loads(VALID_INDICATOR)

    def test_wellformed_indicator(self):
        results = validate_string(VALID_INDICATOR, self.options)
        self.assertTrue(results.is_valid)

    def test_invalid_timestamp(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['created'] = "2016-04-31T20:03:48Z"
        self.assertFalseWithOptions(indicator)

        indicator['created'] = "2016-04-06T20:03:48.000123Z"
        self.assertFalseWithOptions(indicator)

        indicator['modified'] = "2016-04-06T20:03:48.001Z"
        self.assertTrueWithOptions(indicator)

        indicator['valid_from'] = "2016-04-06T20:03:48.000123Z"
        indicator['valid_until'] = "2016-04-06T20:03:48.000Z"
        self.assertFalseWithOptions(indicator)

        indicator['valid_until'] = "2016-04-06T20:03:48.001Z"
        self.assertTrueWithOptions(indicator)

    def test_invalid_lang(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['lang'] = "foo"
        self.assertFalseWithOptions(indicator)

        indicator['lang'] = "en"
        self.assertTrueWithOptions(indicator)

    def test_custom_property_name_invalid_character(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['my_new_property!'] = "abc123"
        results = validate_parsed_json(indicator, self.options)
        self.assertEqual(results.is_valid, False)

    def test_custom_property_name_short(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['mp'] = "abc123"
        results = validate_parsed_json(indicator, self.options)
        self.assertEqual(results.is_valid, False)

    def test_custom_property_name_long(self):
        indicator = copy.deepcopy(self.valid_indicator)
        long_property_name = 'my_new_property_' * 16
        indicator[long_property_name] = "abc123"
        results = validate_parsed_json(indicator, self.options)
        self.assertEqual(results.is_valid, False)

    def test_custom_property_name_strict(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['foobar'] = "abc123"
        self.assertFalseWithOptions(indicator, strict_properties=True)

    def test_empty_list(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['my_new_property'] = []
        results = validate_parsed_json(indicator, self.options)
        self.assertEqual(results.is_valid, False)

    def test_id_type(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['id'] = "something--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
        results = validate_parsed_json(indicator, self.options)
        self.assertEqual(results.is_valid, False)

    def test_reserved_property_severity(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['severity'] = "Something"
        results = validate_parsed_json(indicator, self.options)
        self.assertEqual(results.is_valid, False)

    def test_reserved_property_action(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['action'] = "Something"
        results = validate_parsed_json(indicator, self.options)
        self.assertEqual(results.is_valid, False)

    def test_reserved_property_usernames(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['usernames'] = "Something"
        results = validate_parsed_json(indicator, self.options)
        self.assertEqual(results.is_valid, False)

    def test_reserved_property_phone_numbers(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['phone_numbers'] = "Something"
        results = validate_parsed_json(indicator, self.options)
        self.assertEqual(results.is_valid, False)

    def test_reserved_object_type_incident(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['type'] = "incident"
        results = validate_parsed_json(indicator, self.options)
        self.assertEqual(results.is_valid, False)

    def test_reserved_object_type_infrastructure(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['type'] = "infrastructure"
        results = validate_parsed_json(indicator, self.options)
        self.assertEqual(results.is_valid, False)

    def test_vocab_indicator_types(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['indicator_types'] = ["suspicious"]
        results = validate_parsed_json(indicator, self.options)
        self.assertEqual(results.is_valid, False)

        self.check_ignore(indicator, 'indicator-types')

    def test_invalid_pattern(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['pattern'] = """[file:hashes."SHA-256" = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']"""
        self.assertFalseWithOptions(indicator)

    def test_pattern_custom_invalid_format(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['pattern'] = """[ab:yz = 'something']"""
        self.assertFalseWithOptions(indicator)

    def test_pattern_custom_object_type_too_short(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['pattern'] = """[f:name = 'something']"""
        self.assertFalseWithOptions(indicator)

    def test_pattern_custom_object_type_valid(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['pattern'] = """[foo:name = 'something']"""
        self.assertTrueWithOptions(indicator)

    def test_pattern_custom_object_type_strict(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['pattern'] = """[x-x-foo:x_x_name = 'something']"""
        self.assertTrueWithOptions(indicator)

        self.assertFalseWithOptions(indicator, strict_types=True)

    def test_pattern_custom_property_too_short(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['pattern'] = """[file:n = 'something']"""
        self.assertFalseWithOptions(indicator)

    def test_pattern_custom_property_valid(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['pattern'] = """[file:foo = 'something']"""
        self.assertTrueWithOptions(indicator)

    def test_pattern_custom_object_noprefix(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['pattern'] = """[foo:name = 'something']"""
        self.assertFalseWithOptions(indicator, disabled='extensions-use')

        self.check_ignore(indicator, 'custom-prefix,custom-prefix-lax,extensions-use')
        self.assertFalseWithOptions(indicator, disabled='custom-prefix,extensions-use')

    def test_pattern_custom_object_prefix_strict(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['pattern'] = """[x-x-foo:x_x_name = 'something']"""
        self.assertTrueWithOptions(indicator, disabled='extensions-use')

        self.assertFalseWithOptions(indicator, strict_types=True)

    def test_pattern_custom_object_prefix_lax(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['pattern'] = """[x-foo:x_name = 'something']"""
        self.check_ignore(indicator, 'custom-prefix,extensions-use')

    def test_pattern_custom_property_prefix_strict(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['pattern'] = """[file:x_x_name = 'something']"""
        self.assertTrueWithOptions(indicator, disabled='extensions-use')

        self.assertFalseWithOptions(indicator, strict_properties=True, disabled='extensions-use')

    def test_pattern_list_object_property(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['pattern'] = """[windows-registry-key:values[*].data='badstuff']"""
        self.assertTrueWithOptions(indicator)

    def test_pattern_with_escaped_slashes(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['pattern'] = "[windows-registry-key:key LIKE 'HKEY_LOCAL_MACHINE\\\\Foo\\\\Bar%']"
        self.assertTrueWithOptions(indicator)

    def test_additional_schema(self):
        indicator = copy.deepcopy(self.valid_indicator)
        self.assertFalseWithOptions(indicator, schema_dir=self.custom_schemas)

        indicator['name'] = "Foobar"
        self.assertTrueWithOptions(indicator, schema_dir=self.custom_schemas)

    def test_additional_schema_extension(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['name'] = "Foobar"
        indicator['extensions'] = {'extension-definition--993ce403-6fdd-4efa-8279-31cf2d91b1c8': {
            "extension_type": "toplevel-property-extension",
        }}
        self.assertFalseWithOptions(indicator, schema_dir=self.custom_schemas)

        indicator['grade'] = "a"
        self.assertFalseWithOptions(indicator, schema_dir=self.custom_schemas)

        indicator['grade'] = "A"
        self.assertTrueWithOptions(indicator, schema_dir=self.custom_schemas)

    def test_additional_schema_custom_type(self):
        # no schema exists for this type or extension
        new_obj = {
            "type": "x-type",
            "spec_version": "2.1",
            "id": "x-type--353ed279-5f4f-4a79-bffc-b2e2ed08ea1f",
            "created": "2016-04-06T20:03:48.000Z",
            "modified": "2016-04-06T20:03:48.000Z",
            "property1": 10,
            "property2": "fizzbuzz",
            "extensions": {
                "extension-definition--ba73205e-96bb-40d3-8168-0056d862b229": {
                    "extension_type": "new-sdo"
                }
            }
        }
        self.assertFalseWithOptions(new_obj, schema_dir=self.custom_schemas, strict_types=True)
        self.assertTrueWithOptions(new_obj, schema_dir=self.custom_schemas)

        # properties are wrong types (str vs int)
        new_obj['type'] = 'x-new-type'
        new_obj['id'] = 'x-new-type--353ed279-5f4f-4a79-bffc-b2e2ed08ea1f'
        self.assertFalseWithOptions(new_obj, schema_dir=self.custom_schemas)

        # now they're valid
        new_obj['property1'] = 'fizzbuzz'
        new_obj['property2'] = 10
        self.assertTrueWithOptions(new_obj, schema_dir=self.custom_schemas)

    def test_additional_schema_custom_type_invalid_schema(self):
        self.assertFalseWithOptions(ADDTNL_INVALID_SCHEMA, schema_dir=self.custom_schemas)

    def test_validate_parsed_json_list_additional_invalid_schema(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['name'] = 'Foobar'
        objects = [indicator, ADDTNL_INVALID_SCHEMA]
        options = ValidationOptions(schema_dir=self.custom_schemas, version="2.1")
        results = validate_parsed_json(objects, options)
        assert results[0].is_valid
        assert not results[1].is_valid

    def test_indicator_missing_name(self):
        indicator = copy.deepcopy(self.valid_indicator)
        del indicator['name']
        self.assertFalseWithOptions(indicator)

        self.check_ignore(indicator, 'indicator-properties')

    def test_indicator_missing_description(self):
        indicator = copy.deepcopy(self.valid_indicator)
        del indicator['description']
        self.assertFalseWithOptions(indicator)

        self.check_ignore(indicator, 'indicator-properties')

    def test_indicator_missing_name_description(self):
        indicator = copy.deepcopy(self.valid_indicator)
        del indicator['name']
        del indicator['description']
        self.assertFalseWithOptions(indicator)

        self.check_ignore(indicator, 'indicator-properties')

    def test_indicator_different_pattern_type_does_not_get_validated(self):
        pattern = ("alert tcp any any <> any 80 (msg:\"SHA256 Alert\";"
                   " protected_content:\"56D6F32151AD8474F40D7B939C2161EE2BBF10023F4AF1DBB3E13260EBDC6342\";"
                   " hash:sha256; offset:0; length:4;)")
        indicator = copy.deepcopy(self.valid_indicator)
        indicator["pattern"] = pattern
        indicator["pattern_type"] = "snort"
        indicator["pattern_version"] = "2.9.15"

        self.assertTrueWithOptions(indicator)
        self.assertTrueWithOptions(indicator, strict_types=True)
        self.assertTrueWithOptions(indicator, strict_properties=True)

    def test_indicator_different_pattern_type_not_in_enum(self):
        pattern = ("signature example-signature {"
                   "ip-proto == tcp"
                   "dst-port == 80"
                   "payload /^Some expression/"
                   "}")
        indicator = copy.deepcopy(self.valid_indicator)
        indicator["pattern"] = pattern
        indicator["pattern_type"] = "zeek"
        indicator["pattern_version"] = "3.0.1"

        self.assertFalseWithOptions(indicator)
        self.check_ignore(indicator, 'indicator-pattern-types')

    def test_indicator_no_pattern(self):
        indicator = copy.deepcopy(self.valid_indicator)
        del indicator["pattern"]

        self.assertFalseWithOptions(indicator)

    def test_indicator_no_pattern_type(self):
        indicator = copy.deepcopy(self.valid_indicator)
        del indicator["pattern_type"]

        self.assertFalseWithOptions(indicator)

    def test_pattern_custom_sco(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator["pattern"] = "[x-foo-bar:bizz MATCHES 'buzz']"

        self.assertTrueWithOptions(indicator)
        self.assertTrueWithOptions(indicator, strict_properties=True)
