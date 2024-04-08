import copy
import json

from . import ValidatorTest
from ... import validate_parsed_json, validate_string

VALID_OBSERVED_DATA_DEFINITION = u"""
{
  "type": "observed-data",
  "id": "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
  "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
  "created": "2016-04-06T19:58:16.000Z",
  "modified": "2016-04-06T19:58:16.000Z",
  "first_observed": "2015-12-21T19:00:00Z",
  "last_observed": "2015-12-21T19:00:00Z",
  "number_observed": 50,
  "objects": {
    "0": {
      "type": "file",
      "name": "foo.zip",
      "hashes": {
        "MD5": "B365B9A80A06906FC9B400C06C33FF43"
      },
      "mime_type": "application/zip",
      "extensions": {
        "archive-ext": {
          "contains_refs": [
            "1"
          ],
          "version": "5.0"
        }
      }
    },
    "1": {
      "type": "file",
      "hashes": {
        "MD5": "A2FD2B3F4D5A1BD5E7D283299E01DCE9"
      },
      "name": "qwerty.dll"
    }
  },
  "granular_markings": [
    {
      "marking_ref": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
      "selectors": [ "objects.0.type" ]
    }
  ]
}
"""


class ObservedDataTestCases(ValidatorTest):
    valid_observed_data = json.loads(VALID_OBSERVED_DATA_DEFINITION)

    def test_wellformed_observed_data(self):
        results = validate_string(VALID_OBSERVED_DATA_DEFINITION, self.options)
        self.assertTrue(results.is_valid)

    def test_number_observed(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['number_observed'] = -1
        self.assertFalseWithOptions(observed_data)

    def test_selector_invalid_property(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['granular_markings'][0]['selectors'][0] = "foobar"
        self.assertFalseWithOptions(observed_data)

    def test_selector_invalid_index(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['granular_markings'][0]['selectors'] = [
            "objects.0.extensions.archive-ext.contains_refs.[5]"
        ]
        self.assertFalseWithOptions(observed_data)

    def test_selector_invalid_list(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['granular_markings'][0]['selectors'] = [
          "objects.[0].extensions"
        ]
        self.assertFalseWithOptions(observed_data)

    def test_selector_invalid_property2(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['granular_markings'][0]['selectors'] = [
          "objects.[0].extensions.archive-ext.contains_refs.[0].type"
        ]
        self.assertFalseWithOptions(observed_data)

    def test_selectors_multiple(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['granular_markings'][0]['selectors'] = [
          "objects.0.extensions.archive-ext.contains_refs.[5]",
          "objects.0.addons",
          "objects.9"
        ]
        results = validate_parsed_json(observed_data, self.options)
        self.assertTrue(len(results.errors) == 3)
        self.assertFalse(results.is_valid)

    def test_dict_key_uppercase(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['x_s_dicts'] = {
            'FOOBAR': {
                "foo": "bar"
            }
        }
        results = validate_parsed_json(observed_data, self.options)
        self.assertTrue(len(results.errors) == 1)
        self.assertFalse(results.is_valid)

        self.check_ignore(observed_data, 'observable-dictionary-keys')

    def test_dict_key_length(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['x_s_dicts'] = {
            'foofoobarfoofoobarbarfoofoobarbarbar': {
                "foo": "bar"
            }
        }
        results = validate_parsed_json(observed_data, self.options)
        self.assertTrue(len(results.errors) == 1)
        self.assertFalse(results.is_valid)

        self.check_ignore(observed_data, 'observable-dictionary-keys')

    def test_vocab_account_type(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
            "type": "user-account",
            "user_id": "1001",
            "account_login": "bwayne",
            "account_type": "superhero"
        }
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data, 'account-type')

    def test_vocab_windows_pebinary_type(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['extensions']['windows-pebinary-ext'] = {
            "pe_type": "elf"
        }
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data, 'windows-pebinary-type')

    def test_vocab_encryption_algo(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['encryption_algorithm'] = "AES128-ECB"
        self.assertFalseWithOptions(observed_data)

        observed_data['objects']['0']['is_encrypted'] = True
        self.assertTrueWithOptions(observed_data)

        observed_data['objects']['0']['encryption_algorithm'] = "FOO"
        self.assertFalseWithOptions(observed_data)
        self.check_ignore(observed_data, 'encryption-algo')

    def test_vocab_file_hashes(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['hashes'] = {
            "something": "foobar"
        }
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data, 'hash-algo')

    def test_vocab_artifact_hashes(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
            "type": "artifact",
            "url": "http://www.example.com/file.txt",
            "hashes": {
                "foo": "B4D33B0C7306351B9ED96578465C5579"
            }
        }
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data, 'hash-algo')

    def test_vocab_certificate_hashes(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
            "type": "x509-certificate",
            "hashes": {
                "foo": "B4D33B0C7306351B9ED96578465C5579"
            }
        }
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data, 'hash-algo')

    def test_vocab_pebinary_sections_hashes(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['extensions']['windows-pebinary-ext'] = {
            "pe_type": "exe",
            "sections": [
                {
                    "name": "CODE",
                    "entropy": 0.061089,
                    "hashes": {
                        "foo": "1C19FC56AEF2048C1CD3A5E67B099350"
                    }
                }
            ]
        }
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data, 'hash-algo')

    def test_vocab_pebinary_optional_header_hashes(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['extensions']['windows-pebinary-ext'] = {
            "pe_type": "exe",
            "optional_header": {
                "hashes": {
                    "foo": "1C19FC56AEF2048C1CD3A5E67B099350"
                }
            }
        }
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data, 'hash-algo')

        observed_data['objects']['0']['extensions']['windows-pebinary-ext']['optional_header']['hashes'] = {
            "x_foo": "1C19FC56AEF2048C1CD3A5E67B099350"
        }
        self.assertTrueWithOptions(observed_data)

    def test_vocab_pebinary_file_header_hashes(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['extensions']['windows-pebinary-ext'] = {
            "pe_type": "exe",
            "file_header_hashes": {
                "foo": "1C19FC56AEF2048C1CD3A5E67B099350"
            }
        }
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data, 'hash-algo')

    def test_vocab_pebinary_multiple_hashes(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['extensions']['windows-pebinary-ext'] = {
            "pe_type": "exe",
            "file_header_hashes": {
                "foo": "1C19FC56AEF2048C1CD3A5E67B099350"
            },
            "optional_header": {
                "hashes": {
                    "foo": "1C19FC56AEF2048C1CD3A5E67B099350"
                }
            }
        }
        results = validate_parsed_json(observed_data, self.options)
        self.assertTrue(len(results.errors) == 2)
        self.assertFalse(results.is_valid)

        self.check_ignore(observed_data, 'hash-algo')

    def test_vocab_ntfs_alternate_data_streams_hashes(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['extensions']['ntfs-ext'] = {
            "alternate_data_streams": [
                  {
                      "name": "second.stream",
                      "size": 25536,
                      "hashes": {
                          "foo": "B4D33B0C7306351B9ED96578465C5579"
                      }
                  }
              ]
        }
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data, 'hash-algo')

    def test_observable_object_keys(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['abc'] = {
            "type": "x509-certificate",
            "hashes": {
                "MD5": "B4D33B0C7306351B9ED96578465C5579"
            }
        }
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data, 'observable-object-keys')

    def test_observable_object_no_type(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        del observed_data['objects']['0']['type']
        self.assertFalseWithOptions(observed_data)

    def test_observable_object_types(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['type'] = "x--foo"
        self.assertFalseWithOptions(observed_data)
        observed_data['objects']['0']['type'] = "FOO"
        self.assertFalseWithOptions(observed_data)
        observed_data['objects']['0']['type'] = "a"
        self.assertFalseWithOptions(observed_data)
        observed_data['objects']['0']['type'] = "foo"
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data, 'custom-prefix,custom-prefix-lax')

        observed_data['objects']['0']['type'] = "x-c-foo"
        self.assertTrueWithOptions(observed_data)
        self.assertFalseWithOptions(observed_data, strict_types=True, strict_properties=True)

    def test_observable_object_types_prefix_lax(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['type'] = "foo"
        self.assertFalseWithOptions(observed_data,
                                    disabled='custom-prefix')
        observed_data['objects']['0']['type'] = "x-foo"
        self.assertFalseWithOptions(observed_data)
        self.check_ignore(observed_data,
                          'custom-prefix')
        self.assertFalseWithOptions(observed_data,
                                    disabled='custom-prefix-lax')

    def test_observable_object_extensions(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['extensions']['foobar'] = {
            "foo": "bar"
        }
        self.assertFalseWithOptions(observed_data)
        self.assertFalseWithOptions(observed_data)
        self.assertFalseWithOptions(observed_data, strict_properties=True)

        self.check_ignore(observed_data,
                          'custom-prefix,custom-prefix-lax')

    def test_observable_object_extensions_prefix_lax(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['extensions']['foobar'] = {
            "foo": "bar"
        }
        self.assertFalseWithOptions(observed_data,
                                    disabled='custom-prefix')

        del observed_data['objects']['0']['extensions']['foobar']
        observed_data['objects']['0']['extensions']['x-foobar'] = {
            "foo": "bar"
        }
        self.assertFalseWithOptions(observed_data)
        self.check_ignore(observed_data,
                          'custom-prefix')
        self.assertFalseWithOptions(observed_data,
                                    disabled='custom-prefix-lax')

    def test_observable_object_custom_properties(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['foo'] = "bar"
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data,
                          'custom-prefix,custom-prefix-lax')
        self.assertFalseWithOptions(observed_data,
                                    disabled='custom-prefix-lax')

    def test_observable_object_custom_properties_lax(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['foo'] = "bar"
        self.assertFalseWithOptions(observed_data,
                                    disabled='custom-prefix')

        del observed_data['objects']['0']['foo']
        observed_data['objects']['0']['x_foo'] = "bar"
        self.check_ignore(observed_data,
                          'custom-prefix')
        self.assertFalseWithOptions(observed_data,
                                    disabled='custom-prefix-lax')

    def test_observable_object_custom_properties_strict(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['x_x_foo'] = "bar"
        self.assertFalseWithOptions(observed_data, strict_properties=True)

    def test_observable_object_extension_custom_properties(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['extensions']['archive-ext']['foo'] = "bar"
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data, 'custom-prefix,custom-prefix-lax')

    def test_observable_object_extension_custom_properties_lax(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['extensions']['archive-ext']['foo'] = "bar"
        self.assertFalseWithOptions(observed_data,
                                    disabled='custom-prefix')

        del observed_data['objects']['0']['extensions']['archive-ext']['foo']
        observed_data['objects']['0']['extensions']['archive-ext']['x_foo'] = "bar"
        self.check_ignore(observed_data, 'custom-prefix')
        self.assertFalseWithOptions(observed_data,
                                    disabled='custom-prefix-lax')
        self.assertFalseWithOptions(observed_data,
                                    disabled='custom-prefix',
                                    strict_properties=True)

    def test_observable_object_embedded_custom_properties(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
            "type": "x509-certificate",
            "x509_v3_extensions": {
              "issuer_alternative_name": "Example Corp",
              "foo": "bar"
            }
        }
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data, 'custom-prefix,custom-prefix-lax')

    def test_observable_object_embedded_custom_properties_lax(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
            "type": "x509-certificate",
            "x509_v3_extensions": {
              "issuer_alternative_name": "Example Corp",
              "foo": "bar"
            }
        }
        self.assertFalseWithOptions(observed_data,
                                    disabled='custom-prefix')

        del observed_data['objects']['2']['x509_v3_extensions']['foo']
        observed_data['objects']['2']['x509_v3_extensions']['x_foo'] = "bar"
        self.check_ignore(observed_data, 'custom-prefix')
        self.assertFalseWithOptions(observed_data,
                                    disabled='custom-prefix-lax')
        self.assertFalseWithOptions(observed_data,
                                    disabled='custom-prefix',
                                    strict_properties=True)

    def test_observable_object_embedded_dict_custom_properties(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
            "type": "windows-registry-key",
            "key": "hkey_local_machine\\system\\bar\\foo",
            "values": [
                {
                    "name": "Foo",
                    "data": "qwerty",
                    "data_type": "REG_SZ",
                    "foo": "buzz"
                }
            ]
        }
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data,
                          'custom-prefix,custom-prefix-lax')

    def test_observable_object_embedded_dict_custom_properties_lax(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
            "type": "windows-registry-key",
            "key": "hkey_local_machine\\system\\bar\\foo",
            "values": [
                {
                    "name": "Foo",
                    "data": "qwerty",
                    "data_type": "REG_SZ",
                    "foo": "buzz"
                }
            ]
        }
        self.assertFalseWithOptions(observed_data,
                                    disabled='custom-prefix')

        del observed_data['objects']['2']['values'][0]['foo']
        observed_data['objects']['2']['values'][0]['x_foo'] = "bar"
        self.check_ignore(observed_data, 'custom-prefix')
        self.assertFalseWithOptions(observed_data,
                                    disabled='custom-prefix-lax')
        self.assertFalseWithOptions(observed_data,
                                    disabled='custom-prefix',
                                    strict_properties=True)

    def test_observable_object_extension_embedded_custom_properties(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['extensions']['ntfs-ext'] = {
            "alternate_data_streams": [
                  {
                      "name": "second.stream",
                      "size": 25536,
                      "foo": "bar"
                  }
              ]
        }
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data,
                          'custom-prefix,custom-prefix-lax')

    def test_observable_object_extension_embedded_custom_properties_lax(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['extensions']['ntfs-ext'] = {
            "alternate_data_streams": [
                  {
                      "name": "second.stream",
                      "size": 25536,
                      "foo": "bar"
                  }
              ]
        }
        self.assertFalseWithOptions(observed_data,
                                    disabled='custom-prefix')

        del observed_data['objects']['0']['extensions']['ntfs-ext']['alternate_data_streams'][0]['foo']
        observed_data['objects']['0']['extensions']['ntfs-ext']['alternate_data_streams'][0]['x_foo'] = "bar"
        self.check_ignore(observed_data,
                          'custom-prefix')
        self.assertFalseWithOptions(observed_data,
                                    disabled='custom-prefix-lax')
        self.assertFalseWithOptions(observed_data,
                                    disabled='custom-prefix',
                                    strict_properties=True)

    def test_observable_object_extensions_string(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['extensions'] = 'example:Object-f39f745f-d36b-4dca-9a3e-16bb1c5516f0'
        self.assertFalseWithOptions(observed_data)

    def test_observable_object_property_reference(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
          "type": "directory",
          "path": "C:\\Windows\\System32",
          "contains_refs": ['0']
        }
        self.assertTrueWithOptions(observed_data)

        observed_data['objects']['2']['contains_refs'] = ['999']
        self.assertFalseWithOptions(observed_data)

        observed_data['objects']['3'] = {
          "type": "ipv4-addr",
          "value": "203.0.113.1"
        }
        observed_data['objects']['2']['contains_refs'] = ['3']
        self.assertFalseWithOptions(observed_data)

    def test_observable_object_embedded_property_reference(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['extensions']['archive-ext']['contains_refs'][0] = '999'
        self.assertFalseWithOptions(observed_data)

        observed_data['objects']['2'] = {
          "type": "directory",
          "path": "C:\\Windows\\System32",
          "contains_refs": ['0']
        }
        observed_data['objects']['0']['extensions']['archive-ext']['contains_refs'][0] = '2'
        self.assertFalseWithOptions(observed_data)

    def test_observable_object_reserved_property(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['type'] = 'action'
        self.assertFalseWithOptions(observed_data)

        observed_data['objects']['0']['type'] = 'file'
        observed_data['objects']['0']['action'] = True
        self.assertFalseWithOptions(observed_data)

    def test_windows_registry_key_truncated(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
            "type": "windows-registry-key",
            "key": "HKLM\\system\\bar\\foo"
        }
        self.assertFalseWithOptions(observed_data)

        observed_data['objects']['2']['key'] = "hkey_local_machine\\system\\bar\\foo"
        self.assertTrueWithOptions(observed_data)

    def test_vocab_windows_process_priority(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
            "type": "process",
            "pid": 314,
            "name": "foobar.exe",
            "extensions": {
                "windows-process-ext": {
                    "aslr_enabled": True,
                    "dep_enabled": True,
                    "priority": "HIGH_PRIORITY",
                    "owner_sid": "S-1-5-21-186985262-1144665072-74031268-1309"
                }
            }
        }
        self.assertFalseWithOptions(observed_data)

        observed_data['objects']['2']['extensions']['windows-process-ext']['priority'] = 'HIGH_PRIORITY_CLASS'
        self.assertTrueWithOptions(observed_data)

        self.check_ignore(observed_data, 'windows-process-priority-format')

    def test_file_mime_type(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['mime_type'] = "bla"
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data, 'mime-type')

    def test_artifact_mime_type(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
            "type": "artifact",
            "url": "http://www.example.com/file.txt",
            "hashes": {
                "MD5": "B4D33B0C7306351B9ED96578465C5579"
            },
            "mime_type": "bla/blabla"
        }
        self.assertFalseWithOptions(observed_data)

        observed_data['objects']['2']['mime_type'] = "text/plain"
        self.assertTrueWithOptions(observed_data)

        del observed_data['objects']['2']['url']
        self.assertFalseWithOptions(observed_data)

    def test_file_character_set(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['name_enc'] = "bla.bla.bla"
        self.assertFalseWithOptions(observed_data)

        observed_data['objects']['0']['name_enc'] = "ISO-8859-2"
        self.assertTrueWithOptions(observed_data)

    def test_directory_character_set(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
          "type": "directory",
          "path": "C:\\Windows\\System32",
          "path_enc": "bla.bla.bla"
        }
        self.assertFalseWithOptions(observed_data)

        observed_data['objects']['2']['path_enc'] = "US-ASCII"
        self.assertTrueWithOptions(observed_data)

    def test_pdf_doc_info(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
            "type": "file",
            "name": "foo.pdf",
            "extensions": {
                "pdf-ext": {
                    "version": "1.7",
                    "document_info_dict": {
                        "Title": "Sample document",
                        "foo": "bar"
                    }
                }
            }
        }
        self.assertFalseWithOptions(observed_data)
        self.check_ignore(observed_data, 'pdf-doc-info')

    def test_software_language(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
            "type": "software",
            "name": "word",
            "languages": ["bbb"]
        }
        self.assertFalseWithOptions(observed_data)

        observed_data['objects']['2']['languages'][0] = 'eng'
        self.assertTrueWithOptions(observed_data)

    def test_software_cpe(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
            "type": "software",
            "name": "word",
            "cpe": "invalid",
        }
        self.assertFalseWithOptions(observed_data)

        observed_data['objects']['2']['cpe'] = 'cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*'
        self.assertTrueWithOptions(observed_data)

    def test_email_address_invalid_value(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
            "type": "email-addr",
            "value": "John Doe <jdoe@example.com>",
            "display_name": "John Doe"
        }
        self.assertFalseWithOptions(observed_data)

        observed_data['objects']['2']['value'] = 'jdoe@example.com'
        self.assertTrueWithOptions(observed_data)

    def test_email_message_multipart(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
          "type": "email-addr",
          "value": "jdoe@example.com",
          "display_name": "John Doe"
        }
        observed_data['objects']['3'] = {
          "type": "email-addr",
          "value": "mary@example.com",
          "display_name": "Mary Smith"
        }
        observed_data['objects']['4'] = {
            "type": "email-message",
            "is_multipart": False,
            "from_ref": "2",
            "to_refs": ["3"],
            "date": "1997-11-21T15:55:06Z",
            "subject": "Saying Hello",
            "body_multipart": [
                {
                    "content_type": "text/plain; charset=utf-8",
                    "content_disposition": "inline",
                    "body": "Cats are funny!"
                },
                {
                    "content_type": "image/png",
                    "content_disposition": "attachment; filename=\"tabby.png\"",
                },
                {
                    "content_type": "application/zip",
                    "content_disposition": "attachment; filename=\"tabby_pics.zip\"",
                }
            ]

        }
        self.assertFalseWithOptions(observed_data)

        del observed_data['objects']['4']['body_multipart']
        observed_data['objects']['4']['body'] = "Hello World"
        self.assertTrueWithOptions(observed_data)

    def test_email_message_multipart_body_raw_refs(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
            "type": "email-message",
            "is_multipart": True,
            "body_multipart": [
                {
                    "content_type": "text/plain; charset=utf-8",
                    "body": "Cats are cute!"
                },
                {
                    "body_raw_ref": "999"
                }
            ]

        }
        self.assertFalseWithOptions(observed_data)

        observed_data['objects']['2']['body_multipart'][1]['body_raw_ref'] = "0"
        self.assertTrueWithOptions(observed_data)

    def test_artifact_url_payloadbin(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
            "type": "artifact",
            "mime_type": "image/jpeg",
            "payload_bin": "VBORw0KGgoAAAANSUhEUgAAADI==",
            "hashes": {
                "MD5": "69D0D97D02A03C43782DD571394E6869"
            },
            "url": "www.g.com"
        }
        self.assertFalseWithOptions(observed_data)

        del observed_data['objects']['2']['url']
        self.assertTrueWithOptions(observed_data)

        observed_data['objects']['2']['payload_bin'] = "failing test"
        self.assertFalseWithOptions(observed_data)

    def test_file_invalid_is_encrypted(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
            "type": "file",
            "hashes": {
                "MD5": "8D98A25E9D0662B1F4CA3BF22D6F53E9"
            },
            "is_encrypted": False,
            "encryption_algorithm": "RSA"
        }
        self.assertFalseWithOptions(observed_data)

    def test_hash_length(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        hash_name = "abcdefghijklmnopqrstuvwxyz0123456789"
        observed_data['objects']['0']['hashes'][hash_name] = "8D98A25E9D0662B1F4CA3BF22D6F53E9"
        self.assertFalseWithOptions(observed_data)

        observed_data = copy.deepcopy(self.valid_observed_data)
        hash_name = "MD"
        observed_data['objects']['0']['hashes'][hash_name] = "8D98A25E9D0662B1F4CA3BF22D6F53E9"
        self.assertFalseWithOptions(observed_data)

    def test_invalid_accessed_timestamp(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['1']['created'] = "2016-11-31T08:17:27.000000Z"
        self.assertFalseWithOptions(observed_data)

    def test_invalid_extension_timestamp(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['1']['extensions'] = {'windows-pebinary-ext': {
            "pe_type": "dll",
            "time_date_stamp": "2016-11-31T08:17:27Z",
        }}
        self.assertFalseWithOptions(observed_data)

    def test_invalid_observable_embedded_timestamp(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
            "type": "x509-certificate",
            "x509_v3_extensions": {
              "private_key_usage_period_not_before": "2016-11-31T08:17:27.000000Z"
            }
        }
        self.assertFalseWithOptions(observed_data)

    def test_invalid_timestamp(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['created'] = "2016-11-31T08:17:27.000Z"
        self.assertFalseWithOptions(observed_data)

        observed_data['created'] = "2016-04-06T19:58:16.123Z"
        self.assertFalseWithOptions(observed_data)

        observed_data['modified'] = "2016-04-06T19:58:16.123Z"
        self.assertTrueWithOptions(observed_data)

        observed_data['first_observed'] = "2016-11-31T08:17:27.000Z"
        self.assertFalseWithOptions(observed_data)

        observed_data['first_observed'] = "2015-12-21T19:00:00.123Z"
        self.assertFalseWithOptions(observed_data)

        observed_data['last_observed'] = "2015-12-21T19:00:00.123Z"
        self.assertTrueWithOptions(observed_data)

    def test_additional_schemas_custom_observable(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
            "type": "x-new-observable",
            "foo": 100
        }
        self.assertFalseWithOptions(observed_data, schema_dir=self.custom_schemas)

        observed_data['objects']['2']['foo'] = 'something'
        self.assertTrueWithOptions(observed_data, schema_dir=self.custom_schemas)

    def test_additional_schemas_custom_extension(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['1']['extensions'] = {'x-example-com-foobar-ext': {
            "bar_value": "something",
        }}
        self.assertFalseWithOptions(observed_data, schema_dir=self.custom_schemas)

        observed_data['objects']['1']['extensions']['x-example-com-foobar-ext']['foo_value'] = 'something else'
        self.assertTrueWithOptions(observed_data, schema_dir=self.custom_schemas)

    def test_url(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
            "type": "url",
            "value": "foo",
        }
        self.assertFalseWithOptions(observed_data)

        observed_data['objects']['2']['value'] = "http://www.example.com/file.txt"
        self.assertTrueWithOptions(observed_data)

    def test_invalid_objects_property(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects'] = [
            {
                "type": "windows-registry-key",
                "key": "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\WSALG2"
            }
            ]
        self.assertFalseWithOptions(observed_data)

    def test_url_in_artifact(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
            "type": "artifact",
            "url": "foo",
            "hashes": {
                "MD5": "B4D33B0C7306351B9ED96578465C5579"
            },
            "mime_type": "text/plain"
        }
        self.assertFalseWithOptions(observed_data)

        observed_data['objects']['2']['url'] = "http://www.example.com/file.txt"
        self.assertTrueWithOptions(observed_data)
