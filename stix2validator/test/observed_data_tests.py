import unittest
import copy
import json
from . import ValidatorTest
from .. import validate_string

VALID_OBSERVED_DATA_DEFINITION = """
{
  "type": "observed-data",
  "id": "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
  "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
  "created": "2016-04-06T19:58:16Z",
  "modified": "2016-04-06T19:58:16Z",
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
        observed_data = json.dumps(observed_data)
        self.assertFalseWithOptions(observed_data)

    def test_selector_invalid_property(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['granular_markings'][0]['selectors'][0] = "foobar"
        observed_data = json.dumps(observed_data)
        self.assertFalseWithOptions(observed_data)

    def test_selector_invalid_index(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['granular_markings'][0]['selectors'] = [
            "objects.0.extensions.archive-ext.contains_refs.[5]"
        ]
        observed_data = json.dumps(observed_data)
        self.assertFalseWithOptions(observed_data)

    def test_selector_invalid_list(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['granular_markings'][0]['selectors'] = [
          "objects.[0].extensions"
        ]
        observed_data = json.dumps(observed_data)
        self.assertFalseWithOptions(observed_data)

    def test_selector_invalid_property2(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['granular_markings'][0]['selectors'] = [
          "objects.[0].extensions.archive-ext.contains_refs.[0].type"
        ]
        observed_data = json.dumps(observed_data)
        self.assertFalseWithOptions(observed_data)

    def test_selectors_multiple(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['granular_markings'][0]['selectors'] = [
          "objects.0.extensions.archive-ext.contains_refs.[5]",
          "objects.0.addons",
          "objects.9"
        ]
        observed_data = json.dumps(observed_data)
        results = validate_string(observed_data, self.options)
        self.assertTrue(len(results.errors) == 3)
        self.assertFalse(results.is_valid)

    def test_dict_key_uppercase(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['x_s_dicts'] = {
            'FOOBAR': {
                "foo": "bar"
            }
        }
        observed_data = json.dumps(observed_data)
        results = validate_string(observed_data, self.options)
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
        observed_data = json.dumps(observed_data)
        results = validate_string(observed_data, self.options)
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
        observed_data = json.dumps(observed_data)
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data, 'account-type')

    def test_vocab_windows_pebinary_type(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['extensions']['windows-pebinary-ext'] = {
            "pe_type": "elf"
        }
        observed_data = json.dumps(observed_data)
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data, 'windows-pebinary-type')

    def test_vocab_encryption_algo(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['encryption_algorithm'] = "AES128-ECB"
        self.assertFalseWithOptions(json.dumps(observed_data))

        observed_data['objects']['0']['is_encrypted'] = True
        self.assertTrueWithOptions(json.dumps(observed_data))

        observed_data['objects']['0']['encryption_algorithm'] = "FOO"
        self.assertFalseWithOptions(json.dumps(observed_data))
        self.check_ignore(json.dumps(observed_data), 'encryption-algo')

    def test_vocab_file_hashes(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['hashes'] = {
            "something": "foobar"
        }
        observed_data = json.dumps(observed_data)
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
        observed_data = json.dumps(observed_data)
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
        observed_data = json.dumps(observed_data)
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
        observed_data = json.dumps(observed_data)
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
        self.assertFalseWithOptions(json.dumps(observed_data))

        self.check_ignore(json.dumps(observed_data), 'hash-algo')

        observed_data['objects']['0']['extensions']['windows-pebinary-ext']['optional_header']['hashes'] = {
            "x_foo": "1C19FC56AEF2048C1CD3A5E67B099350"
        }
        self.assertTrueWithOptions(json.dumps(observed_data))

    def test_vocab_pebinary_file_header_hashes(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['extensions']['windows-pebinary-ext'] = {
            "pe_type": "exe",
            "file_header_hashes": {
                "foo": "1C19FC56AEF2048C1CD3A5E67B099350"
            }
        }
        observed_data = json.dumps(observed_data)
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
        observed_data = json.dumps(observed_data)
        results = validate_string(observed_data, self.options)
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
        observed_data = json.dumps(observed_data)
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
        observed_data = json.dumps(observed_data)
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data, 'observable-object-keys')

    def test_observable_object_types(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['type'] = "x--foo"
        self.assertFalseWithOptions(json.dumps(observed_data))
        observed_data['objects']['0']['type'] = "FOO"
        self.assertFalseWithOptions(json.dumps(observed_data))
        observed_data['objects']['0']['type'] = "a"
        self.assertFalseWithOptions(json.dumps(observed_data))
        observed_data['objects']['0']['type'] = "foo"
        self.assertFalseWithOptions(json.dumps(observed_data))

        self.check_ignore(json.dumps(observed_data),
                          'custom-observable-object-prefix,custom-observable-object-prefix-lax')

        observed_data['objects']['0']['type'] = "x-c-foo"
        self.assertTrueWithOptions(json.dumps(observed_data))
        self.assertFalseWithOptions(json.dumps(observed_data), strict_types=True)

    def test_observable_object_types_prefix_lax(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['type'] = "foo"
        self.assertFalseWithOptions(json.dumps(observed_data),
                                    disabled='custom-observable-object-prefix')
        observed_data['objects']['0']['type'] = "x-foo"
        self.assertFalseWithOptions(json.dumps(observed_data))
        self.check_ignore(json.dumps(observed_data),
                          'custom-observable-object-prefix')
        self.assertFalseWithOptions(json.dumps(observed_data),
                                    disabled='custom-observable-object-prefix-lax')

    def test_observable_object_extensions(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['extensions']['foobar'] = {
            "foo": "bar"
        }
        observed_data = json.dumps(observed_data)
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data,
                          'custom-object-extension-prefix,custom-object-extension-prefix-lax')

    def test_observable_object_extensions_prefix_lax(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['extensions']['foobar'] = {
            "foo": "bar"
        }
        self.assertFalseWithOptions(json.dumps(observed_data),
                                    disabled='custom-object-extension-prefix')

        del observed_data['objects']['0']['extensions']['foobar']
        observed_data['objects']['0']['extensions']['x-foobar'] = {
            "foo": "bar"
        }
        self.assertFalseWithOptions(json.dumps(observed_data))
        self.check_ignore(json.dumps(observed_data),
                          'custom-object-extension-prefix')
        self.assertFalseWithOptions(json.dumps(observed_data),
                                    disabled='custom-object-extension-prefix-lax')

    def test_observable_object_custom_properties(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['foo'] = "bar"
        observed_data = json.dumps(observed_data)
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data,
                          'custom-observable-properties-prefix,custom-observable-properties-prefix-lax')
        self.assertFalseWithOptions(observed_data,
                                    disabled='custom-observable-properties-prefix-lax')

    def test_observable_object_custom_properties_lax(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['foo'] = "bar"
        self.assertFalseWithOptions(json.dumps(observed_data),
                                    disabled='custom-observable-properties-prefix')

        del observed_data['objects']['0']['foo']
        observed_data['objects']['0']['x_foo'] = "bar"
        self.check_ignore(json.dumps(observed_data),
                          'custom-observable-properties-prefix')
        self.assertFalseWithOptions(json.dumps(observed_data),
                                    disabled='custom-observable-properties-prefix-lax')

    def test_observable_object_extension_custom_properties(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['extensions']['archive-ext']['foo'] = "bar"
        observed_data = json.dumps(observed_data)
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data,
                          'custom-observable-properties-prefix,custom-observable-properties-prefix-lax')

    def test_observable_object_extension_custom_properties_lax(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['extensions']['archive-ext']['foo'] = "bar"
        self.assertFalseWithOptions(json.dumps(observed_data),
                                    disabled='custom-observable-properties-prefix')

        del observed_data['objects']['0']['extensions']['archive-ext']['foo']
        observed_data['objects']['0']['extensions']['archive-ext']['x_foo'] = "bar"
        self.check_ignore(json.dumps(observed_data),
                          'custom-observable-properties-prefix')
        self.assertFalseWithOptions(json.dumps(observed_data),
                                    disabled='custom-observable-properties-prefix-lax')

    def test_observable_object_embedded_custom_properties(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
            "type": "x509-certificate",
            "x509_v3_extensions": {
              "foo": "bar"
            }
        }
        observed_data = json.dumps(observed_data)
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data,
                          'custom-observable-properties-prefix,custom-observable-properties-prefix-lax')

    def test_observable_object_embedded_custom_properties_lax(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
            "type": "x509-certificate",
            "x509_v3_extensions": {
              "foo": "bar"
            }
        }
        self.assertFalseWithOptions(json.dumps(observed_data),
                                    disabled='custom-observable-properties-prefix')

        del observed_data['objects']['2']['x509_v3_extensions']['foo']
        observed_data['objects']['2']['x509_v3_extensions']['x_foo'] = "bar"
        self.check_ignore(json.dumps(observed_data),
                          'custom-observable-properties-prefix')
        self.assertFalseWithOptions(json.dumps(observed_data),
                                    disabled='custom-observable-properties-prefix-lax')

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
        observed_data = json.dumps(observed_data)
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data,
                          'custom-observable-properties-prefix,custom-observable-properties-prefix-lax')

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
        self.assertFalseWithOptions(json.dumps(observed_data),
                                    disabled='custom-observable-properties-prefix')

        del observed_data['objects']['2']['values'][0]['foo']
        observed_data['objects']['2']['values'][0]['x_foo'] = "bar"
        self.check_ignore(json.dumps(observed_data),
                          'custom-observable-properties-prefix')
        self.assertFalseWithOptions(json.dumps(observed_data),
                                    disabled='custom-observable-properties-prefix-lax')

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
        observed_data = json.dumps(observed_data)
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data,
                          'custom-observable-properties-prefix,custom-observable-properties-prefix-lax')

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
        self.assertFalseWithOptions(json.dumps(observed_data),
                                    disabled='custom-observable-properties-prefix')

        del observed_data['objects']['0']['extensions']['ntfs-ext']['alternate_data_streams'][0]['foo']
        observed_data['objects']['0']['extensions']['ntfs-ext']['alternate_data_streams'][0]['x_foo'] = "bar"
        self.check_ignore(json.dumps(observed_data),
                          'custom-observable-properties-prefix')
        self.assertFalseWithOptions(json.dumps(observed_data),
                                    disabled='custom-observable-properties-prefix-lax')

    def test_observable_object_property_reference(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
          "type": "directory",
          "path": "C:\\Windows\\System32",
          "contains_refs": ['0']
        }
        self.assertTrueWithOptions(json.dumps(observed_data))

        observed_data['objects']['2']['contains_refs'] = ['999']
        self.assertFalseWithOptions(json.dumps(observed_data))

        observed_data['objects']['3'] = {
          "type": "ipv4-addr",
          "value": "203.0.113.1"
        }
        observed_data['objects']['2']['contains_refs'] = ['3']
        self.assertFalseWithOptions(json.dumps(observed_data))

    def test_observable_object_embedded_property_reference(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['extensions']['archive-ext']['contains_refs'][0] = '999'
        self.assertFalseWithOptions(json.dumps(observed_data))

        observed_data['objects']['2'] = {
          "type": "directory",
          "path": "C:\\Windows\\System32",
          "contains_refs": ['0']
        }
        observed_data['objects']['0']['extensions']['archive-ext']['contains_refs'][0] = '2'
        self.assertFalseWithOptions(json.dumps(observed_data))

    def test_observable_object_reserved_property(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['type'] = 'action'
        self.assertFalseWithOptions(json.dumps(observed_data))

        observed_data['objects']['0']['type'] = 'file'
        observed_data['objects']['0']['action'] = True
        self.assertFalseWithOptions(json.dumps(observed_data))

    def test_windows_registry_key_truncated(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
            "type": "windows-registry-key",
            "key": "HKLM\\system\\bar\\foo"
        }
        self.assertFalseWithOptions(json.dumps(observed_data))

        observed_data['objects']['2']['key'] = "hkey_local_machine\\system\\bar\\foo"
        self.assertTrueWithOptions(json.dumps(observed_data))

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
        self.assertFalseWithOptions(json.dumps(observed_data))

        observed_data['objects']['2']['extensions']['windows-process-ext']['priority'] = 'HIGH_PRIORITY_CLASS'
        self.assertTrueWithOptions(json.dumps(observed_data))

        self.check_ignore(json.dumps(observed_data), 'windows-process-priority-format')

    def test_file_mime_type(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['mime_type'] = "bla"
        observed_data = json.dumps(observed_data)
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
        self.assertFalseWithOptions(json.dumps(observed_data))

        observed_data['objects']['2']['mime_type'] = "text/plain"
        self.assertTrueWithOptions(json.dumps(observed_data))

        del observed_data['objects']['2']['url']
        self.assertFalseWithOptions(json.dumps(observed_data))

    def test_file_character_set(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['0']['name_enc'] = "bla.bla.bla"
        self.assertFalseWithOptions(json.dumps(observed_data))

        observed_data['objects']['0']['name_enc'] = "ISO-8859-2"
        self.assertTrueWithOptions(json.dumps(observed_data))

    def test_directory_character_set(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
          "type": "directory",
          "path": "C:\\Windows\\System32",
          "path_enc": "bla.bla.bla"
        }
        self.assertFalseWithOptions(json.dumps(observed_data))

        observed_data['objects']['2']['path_enc'] = "US-ASCII"
        self.assertTrueWithOptions(json.dumps(observed_data))

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
        self.assertFalseWithOptions(json.dumps(observed_data))
        self.check_ignore(json.dumps(observed_data), 'pdf-doc-info')

    def test_software_language(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
            "type": "software",
            "name": "word",
            "languages": ["bbb"]
        }
        self.assertFalseWithOptions(json.dumps(observed_data))

        observed_data['objects']['2']['languages'][0] = 'eng'
        self.assertTrueWithOptions(json.dumps(observed_data))

    def test_email_address_invalid_value(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['objects']['2'] = {
            "type": "email-addr",
            "value": "John Doe <jdoe@example.com>",
            "display_name": "John Doe"
        }
        self.assertFalseWithOptions(json.dumps(observed_data))

        observed_data['objects']['2']['value'] = 'jdoe@example.com'
        self.assertTrueWithOptions(json.dumps(observed_data))

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
        self.assertFalseWithOptions(json.dumps(observed_data))

        del observed_data['objects']['4']['body_multipart']
        observed_data['objects']['4']['body'] = "Hello World"
        self.assertTrueWithOptions(json.dumps(observed_data))

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
        self.assertFalseWithOptions(json.dumps(observed_data))

        observed_data['objects']['2']['body_multipart'][1]['body_raw_ref'] = "0"
        self.assertTrueWithOptions(json.dumps(observed_data))

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
        self.assertFalseWithOptions(json.dumps(observed_data))

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
        self.assertFalseWithOptions(json.dumps(observed_data))


if __name__ == "__main__":
    unittest.main()
