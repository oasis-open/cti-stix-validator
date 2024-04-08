import copy
import json

from . import ValidatorTest
from ... import validate_parsed_json, validate_string

VALID_OBSERVED_DATA_DEFINITION = u"""
{
  "type": "observed-data",
  "spec_version": "2.1",
  "id": "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
  "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
  "created": "2016-04-06T19:58:16.000Z",
  "modified": "2016-04-06T19:58:16.000Z",
  "first_observed": "2015-12-21T19:00:00.000Z",
  "last_observed": "2015-12-21T19:00:00.000Z",
  "number_observed": 50,
  "object_refs": [
    "ipv4-address--efcd5e80-570d-4131-b213-62cb18eaa6a8",
    "domain-name--ecb120bf-2694-4902-a737-62b74539a41b"
  ]
}
"""

VALID_OBJECT = u"""
{
      "type": "file",
      "id": "file--ff1e0780-358c-5808-a8c7-d0fca4ef6ef4",
      "spec_version": "2.1",
      "name": "foo.zip",
      "hashes": {
        "MD5": "B365B9A80A06906FC9B400C06C33FF43"
      },
      "mime_type": "application/zip",
      "extensions": {
        "ntfs-ext": {
          "alternate_data_streams": [
            {
              "name": "second.stream",
              "size": 25536
            }
          ]
        }
      }
}
"""


class ObservedDataTestCases(ValidatorTest):
    valid_observed_data = json.loads(VALID_OBSERVED_DATA_DEFINITION)
    valid_object = json.loads(VALID_OBJECT)

    def test_wellformed_observed_data(self):
        results = validate_string(VALID_OBSERVED_DATA_DEFINITION, self.options)
        self.assertTrue(results.is_valid)

    def test_number_observed(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['number_observed'] = -1
        self.assertFalseWithOptions(observed_data)

    def test_dict_key_uppercase(self):
        observed_data = {
            "type": "file",
            "id": "file--ff1e0780-358c-5808-a8c7-d0fca4ef6ef4",
            "name": "foo.zip",
            "x_s_dicts": {
                "FOOBAR": {
                     "foo": "bar"
                }
            }
        }
        self.assertFalseWithOptions(observed_data, disabled='extensions-use')

        self.check_ignore(observed_data, 'observable-dictionary-keys,extensions-use')

    def test_dict_key_length(self):
        observed_data = {
            "type": "file",
            "id": "file--ff1e0780-358c-5808-a8c7-d0fca4ef6ef4",
            "name": "foo.zip",
            "x_s_dicts": {
                "foofoobarfoofoobarbarfoofoobarbarbar": {
                    "foo": "bar"
                }
            },
        }
        # STIX 2.1 removed dictionary key minimum length
        self.assertTrueWithOptions(observed_data, disabled='extensions-use')

    def test_vocab_account_type(self):
        observed_data = {
            "type": "user-account",
            "id": "user-account--ff1e0780-358c-5808-a8c7-d0fca4ef6ef4",
            "user_id": "1001",
            "account_login": "bwayne",
            "account_type": "superhero"
        }
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data, 'account-type')

    def test_vocab_windows_pebinary_type(self):
        observed_data = copy.deepcopy(self.valid_object)
        observed_data['extensions']['windows-pebinary-ext'] = {
            "pe_type": "elf",
            "machine_hex": "014c",
        }
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data, 'windows-pebinary-type')

    def test_vocab_encryption_algo(self):
        observed_data = {
            "type": "artifact",
            "id": "artifact--ff1e0780-358c-5808-a8c7-d0fca4ef6ef4",
            "mime_type": "application/zip",
            "payload_bin": "VBORw0KGgoAAAANSUhEUgAAADI==",
            "encryption_algorithm": "foo",
            "decryption_key": "My voice is my passport"
        }
        self.assertFalseWithOptions(observed_data)

        observed_data['encryption_algorithm'] = "mime-type-indicated"
        self.assertTrueWithOptions(observed_data)

    def test_vocab_file_hashes(self):
        observed_data = copy.deepcopy(self.valid_object)
        observed_data['hashes'] = {
            "something": "foobar"
        }
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data, 'hash-algo')

    def test_vocab_artifact_hashes(self):
        observed_data = {
            "type": "artifact",
            "id": "artifact--ff1e0780-358c-5808-a8c7-d0fca4ef6ef4",
            "url": "http://www.example.com/file.txt",
            "hashes": {
                "foo": "B4D33B0C7306351B9ED96578465C5579"
            }
        }
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data, 'hash-algo')

    def test_vocab_certificate_hashes(self):
        observed_data = {
            "type": "x509-certificate",
            "id": "x509-certificate--ff1e0780-358c-5808-a8c7-d0fca4ef6ef4",
            "hashes": {
                "foo": "B4D33B0C7306351B9ED96578465C5579"
            }
        }
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data, 'hash-algo')

    def test_vocab_pebinary_sections_hashes(self):
        observed_data = copy.deepcopy(self.valid_object)
        observed_data['extensions']['windows-pebinary-ext'] = {
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
        observed_data = copy.deepcopy(self.valid_object)
        observed_data['extensions']['windows-pebinary-ext'] = {
            "pe_type": "exe",
            "optional_header": {
                "hashes": {
                    "foo": "1C19FC56AEF2048C1CD3A5E67B099350"
                }
            }
        }
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data, 'hash-algo')

        observed_data['extensions']['windows-pebinary-ext']['optional_header']['hashes'] = {
            "x_foo": "1C19FC56AEF2048C1CD3A5E67B099350"
        }
        self.assertTrueWithOptions(observed_data)

    def test_vocab_pebinary_file_header_hashes(self):
        observed_data = copy.deepcopy(self.valid_object)
        observed_data['extensions']['windows-pebinary-ext'] = {
            "pe_type": "exe",
            "file_header_hashes": {
                "foo": "1C19FC56AEF2048C1CD3A5E67B099350"
            }
        }
        self.assertFalseWithOptions(observed_data)
        observed_data['extensions']['windows-pebinary-ext'] = {
            "pe_type": "exe",
            "file_header_hashes": {
                "MD5": "1C19FC56AEF2048C1CD3A5E67B099350"
            }
        }
        self.check_ignore(observed_data, 'hash-algo')

    def test_vocab_pebinary_multiple_hashes(self):
        observed_data = copy.deepcopy(self.valid_object)
        observed_data['extensions']['windows-pebinary-ext'] = {
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
        observed_data['extensions']['windows-pebinary-ext'] = {
            "pe_type": "exe",
            "file_header_hashes": {
                "MD5": "1C19FC56AEF2048C1CD3A5E67B099350"
            },
            "optional_header": {
                "hashes": {
                    "MD5": "1C19FC56AEF2048C1CD3A5E67B099350"
                }
            }
        }
        self.check_ignore(observed_data, 'hash-algo')

    def test_vocab_ntfs_alternate_data_streams_hashes(self):
        observed_data = copy.deepcopy(self.valid_object)
        observed_data['extensions']['ntfs-ext'] = {
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

    def test_observable_object_extensions(self):
        observed_data = copy.deepcopy(self.valid_object)
        observed_data['extensions']['foobar-ext'] = {
            "foo": "bar"
        }
        self.assertFalseWithOptions(observed_data, disabled='extensions-use')
        self.assertFalseWithOptions(observed_data, strict_properties=True, disabled='extensions-use')

        self.check_ignore(observed_data,
                          'custom-prefix,custom-prefix-lax,extensions-use')

    def test_observable_object_extensions2(self):
        observed_data = copy.deepcopy(self.valid_object)
        observed_data['extensions']['x-foo-bar-ext'] = {
            "foo": "bar"
        }
        self.assertFalseWithOptions(observed_data)
        self.assertFalseWithOptions(observed_data, strict_properties=True)

        self.check_ignore(observed_data, 'extensions-use')

    def test_observable_object_extensions_prefix_lax(self):
        observed_data = copy.deepcopy(self.valid_object)
        observed_data['extensions']['foobar-ext'] = {
            "foo": "bar"
        }
        self.assertFalseWithOptions(observed_data,
                                    disabled='custom-prefix,extensions-use')

        del observed_data['extensions']['foobar-ext']
        observed_data['extensions']['x-foobar'] = {
            "foo": "bar"
        }
        self.assertFalseWithOptions(observed_data,
                                    disabled='custom-prefix,extensions-use')

        del observed_data['extensions']['x-foobar']
        observed_data['extensions']['x-foobar-ext'] = {
            "foo": "bar"
        }
        self.assertFalseWithOptions(observed_data, disabled='extensions-use')
        self.check_ignore(observed_data,
                          'custom-prefix,extensions-use')
        self.assertFalseWithOptions(observed_data,
                                    disabled='custom-prefix-lax,extensions-use')

    def test_observable_object_custom_properties(self):
        observed_data = copy.deepcopy(self.valid_object)
        observed_data['foo'] = "bar"
        self.assertFalseWithOptions(observed_data, disabled='extensions-use')

        self.check_ignore(observed_data,
                          'custom-prefix,custom-prefix-lax,extensions-use')
        self.assertFalseWithOptions(observed_data,
                                    disabled='custom-prefix-lax,extensions-use')

    def test_observable_object_custom_properties_lax(self):
        observed_data = copy.deepcopy(self.valid_object)
        observed_data['foo'] = "bar"
        self.assertFalseWithOptions(observed_data,
                                    disabled='custom-prefix,extensions-use')

        del observed_data['foo']
        observed_data['x_foo'] = "bar"
        self.check_ignore(observed_data,
                          'custom-prefix,extensions-use')
        self.assertFalseWithOptions(observed_data,
                                    disabled='custom-prefix-lax,extensions-use')

    def test_observable_object_custom_properties_strict(self):
        observed_data = copy.deepcopy(self.valid_object)
        observed_data['x_x_foo'] = "bar"
        self.assertFalseWithOptions(observed_data, strict_properties=True, disabled='extensions-use')

    def test_observable_object_custom_property_without_extension(self):
        observed_data = copy.deepcopy(self.valid_object)
        observed_data['x_foo_something'] = "some value"

        self.assertFalseWithOptions(observed_data)
        self.assertFalseWithOptions(observed_data, strict_properties=True)
        self.assertFalseWithOptions(observed_data, strict_properties=True, disabled='extensions-use')
        self.assertTrueWithOptions(observed_data, disabled='extensions-use')

    def test_observable_object_custom_property_with_extension(self):
        observed_data = copy.deepcopy(self.valid_object)
        observed_data['x_foo_something'] = "some value"
        observed_data['extensions'] = {
            "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
                "extension_type": "property-extension",
                "rank": 5,
                "toxicity": 8
            }
        }

        self.assertFalseWithOptions(observed_data)
        self.assertFalseWithOptions(observed_data, strict_properties=True)
        self.assertFalseWithOptions(observed_data, strict_properties=True, disabled='extensions-use')

        del observed_data['x_foo_something']
        self.assertTrueWithOptions(observed_data, strict_properties=True)

    def test_observable_object_custom_toplevel_property_with_extension(self):
        observed_data = copy.deepcopy(self.valid_object)
        observed_data['x_foo_something'] = "some value"
        observed_data['rank'] = 5
        observed_data['toxicity'] = 8
        observed_data['extensions'] = {
            "extension-definition--a932fcc6-e032-176c-826f-cb970a5a1fff": {
                "extension_type": "toplevel-property-extension",
            }
        }

        self.assertFalseWithOptions(observed_data)
        self.assertFalseWithOptions(observed_data, strict_properties=True)
        self.assertFalseWithOptions(observed_data, strict_properties=True, disabled='extensions-use')

        del observed_data['x_foo_something']
        self.assertFalseWithOptions(observed_data)
        self.assertFalseWithOptions(observed_data, strict_properties=True)
        self.assertFalseWithOptions(observed_data, strict_properties=True, disabled='extensions-use')
        self.assertFalseWithOptions(observed_data, disabled='extensions-use')
        self.assertTrueWithOptions(observed_data, disabled='extensions-use,custom-prefix,custom-prefix-lax')

    def test_observable_object_extension_custom_properties(self):
        observed_data = copy.deepcopy(self.valid_object)
        observed_data['extensions']["ntfs-ext"]['foo'] = "bar"
        self.assertFalseWithOptions(observed_data)
        self.assertFalseWithOptions(observed_data, strict_properties=True)
        self.assertFalseWithOptions(observed_data, strict_properties=True, disabled='extensions-use')
        self.assertTrueWithOptions(observed_data, disabled='extensions-use,custom-prefix,custom-prefix-lax')

        del observed_data['extensions']["ntfs-ext"]['foo']
        observed_data['extensions']["ntfs-ext"]['x_foo'] = "bar"
        self.assertTrueWithOptions(observed_data, disabled='extensions-use,custom-prefix')

        del observed_data['extensions']["ntfs-ext"]['x_foo']
        observed_data['extensions']["ntfs-ext"]['x_org_foo'] = "bar"
        self.assertTrueWithOptions(observed_data, disabled='extensions-use')

    def test_observable_object_embedded_custom_properties(self):
        observed_data = {
            "type": "x509-certificate",
            "id": "x509-certificate--5fcb3990-706e-4fb4-aef2-352c54b034a5",
            "x509_v3_extensions": {
              "issuer_alternative_name": "Example Corp",
              "foo": "bar"
            }
        }
        self.assertFalseWithOptions(observed_data)
        self.assertFalseWithOptions(observed_data, strict_properties=True)
        self.assertFalseWithOptions(observed_data, strict_properties=True, disabled='extensions-use')
        self.assertFalseWithOptions(observed_data, disabled='extensions-use')
        self.assertTrueWithOptions(observed_data, disabled='extensions-use,custom-prefix,custom-prefix-lax')

    def test_observable_object_embedded_dict_custom_properties(self):
        observed_data = {
            "type": "windows-registry-key",
            "id": "windows-registry-key--ff1e0780-358c-5808-a8c7-d0fca4ef6ef4",
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
        self.assertFalseWithOptions(observed_data, strict_properties=True)
        self.assertFalseWithOptions(observed_data, strict_properties=True, disabled='extensions-use')
        self.assertFalseWithOptions(observed_data, disabled='extensions-use')
        self.assertTrueWithOptions(observed_data, disabled='extensions-use,custom-prefix,custom-prefix-lax')

    def test_observable_object_embedded_dict_custom_properties_lax(self):
        observed_data = {
            "type": "windows-registry-key",
            "id": "windows-registry-key--ff1e0780-358c-5808-a8c7-d0fca4ef6ef4",
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
                                    disabled='extensions-use,custom-prefix')

        del observed_data['values'][0]['foo']
        observed_data['values'][0]['x_foo'] = "bar"
        self.check_ignore(observed_data, 'extensions-use,custom-prefix')
        self.assertFalseWithOptions(observed_data,
                                    disabled='extensions-use,custom-prefix-lax')
        self.assertFalseWithOptions(observed_data,
                                    disabled='extensions-use,custom-prefix',
                                    strict_properties=True)

    def test_observable_object_extension_embedded_custom_properties(self):
        observed_data = copy.deepcopy(self.valid_object)
        observed_data['extensions']['ntfs-ext'] = {
            "alternate_data_streams": [
                  {
                      "name": "second.stream",
                      "size": 25536,
                      "foo": "bar"
                  }
              ]
        }
        self.assertFalseWithOptions(observed_data)
        self.assertFalseWithOptions(observed_data, strict_properties=True)
        self.assertFalseWithOptions(observed_data, strict_properties=True, disabled='extensions-use')
        self.assertTrueWithOptions(observed_data, disabled='extensions-use,custom-prefix,custom-prefix-lax')

        del observed_data['extensions']['ntfs-ext']['alternate_data_streams'][0]['foo']
        observed_data['extensions']['ntfs-ext']['alternate_data_streams'][0]['x_foo'] = 'bar'
        self.assertTrueWithOptions(observed_data, disabled='extensions-use,custom-prefix')

        del observed_data['extensions']['ntfs-ext']['alternate_data_streams'][0]['x_foo']
        observed_data['extensions']['ntfs-ext']['alternate_data_streams'][0]['x_org_foo'] = 'bar'
        self.assertTrueWithOptions(observed_data, disabled='extensions-use')

    def test_observable_object_extension_embedded_custom_properties_lax(self):
        observed_data = copy.deepcopy(self.valid_object)
        observed_data['extensions']['ntfs-ext'] = {
            "alternate_data_streams": [
                  {
                      "name": "second.stream",
                      "size": 25536,
                      "foo": "bar",
                  }
              ]
        }
        self.assertFalseWithOptions(observed_data,
                                    disabled='extensions-use,custom-prefix')
        del observed_data['extensions']['ntfs-ext']['alternate_data_streams'][0]['foo']
        observed_data['extensions']['ntfs-ext']['alternate_data_streams'][0]['x_foo'] = "bar"
        self.check_ignore(observed_data,
                          'extensions-use,custom-prefix')
        self.assertFalseWithOptions(observed_data,
                                    disabled='extensions-use,custom-prefix-lax')
        self.assertFalseWithOptions(observed_data,
                                    disabled='extensions-use,custom-prefix',
                                    strict_properties=True)

    def test_observable_object_extensions_string(self):
        observed_data = copy.deepcopy(self.valid_object)
        observed_data['extensions'] = 'example:Object-f39f745f-d36b-4dca-9a3e-16bb1c5516f0'
        self.assertFalseWithOptions(observed_data)

    def test_observable_object_reserved_type(self):
        observed_data = copy.deepcopy(self.valid_object)
        observed_data['type'] = 'action'
        self.assertFalseWithOptions(observed_data)

    def test_observable_object_reserved_property(self):
        observed_data = copy.deepcopy(self.valid_object)
        observed_data['action'] = True
        self.assertFalseWithOptions(observed_data)

    def test_windows_registry_key_truncated(self):
        observed_data = {
            "type": "windows-registry-key",
            "id": "windows-registry-key--ff1e0780-358c-5808-a8c7-d0fca4ef6ef4",
            "key": "HKLM\\system\\bar\\foo"
        }
        self.assertFalseWithOptions(observed_data)

        observed_data["key"] = "hkey_local_machine\\system\\bar\\foo"
        self.assertTrueWithOptions(observed_data)

    def test_vocab_windows_process_priority(self):
        observed_data = {
            "type": "process",
            "id": "process--ff1e0780-358c-4808-a8c7-d0fca4ef6ef4",
            "pid": 314,
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

        observed_data['extensions']['windows-process-ext']['priority'] = 'HIGH_PRIORITY_CLASS'
        self.assertTrueWithOptions(observed_data)

        self.check_ignore(observed_data, 'windows-process-priority-format')

    def test_process_uuidv5(self):
        # Process requires a uuidv4
        observed_data = {
            "type": "process",
            "id": "process--ff1e0780-358c-5808-a8c7-d0fca4ef6ef4",
            "pid": 314,
        }
        self.assertFalseWithOptions(observed_data)

        observed_data['id'] = "process--ff1e0780-358c-4808-a8c7-d0fca4ef6ef4"
        self.assertTrueWithOptions(observed_data)

    def test_uuidv4(self):
        observed_data = copy.deepcopy(self.valid_object)
        observed_data['id'] = "file--ff1e0780-358c-4808-a8c7-d0fca4ef6ef4"
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data, 'uuid-check')

    def test_file_mime_type(self):
        observed_data = copy.deepcopy(self.valid_object)
        observed_data['mime_type'] = "bla"
        self.assertFalseWithOptions(observed_data)

        self.check_ignore(observed_data, 'mime-type')

    def test_artifact_mime_type(self):
        observed_data = {
            "type": "artifact",
            "id": "artifact--ff1e0780-358c-5808-a8c7-d0fca4ef6ef4",
            "url": "http://www.example.com/file.txt",
            "hashes": {
                "MD5": "B4D33B0C7306351B9ED96578465C5579"
            },
            "mime_type": "bla/blabla"
        }
        self.assertFalseWithOptions(observed_data)

        observed_data['mime_type'] = "text/plain"
        self.assertTrueWithOptions(observed_data)

        del observed_data['url']
        self.assertFalseWithOptions(observed_data)

    def test_file_character_set(self):
        observed_data = copy.deepcopy(self.valid_object)
        observed_data['name_enc'] = "bla.bla.bla"
        self.assertFalseWithOptions(observed_data)

        observed_data['name_enc'] = "ISO-8859-2"
        self.assertTrueWithOptions(observed_data)

    def test_directory_character_set(self):
        observed_data = {
          "type": "directory",
          "id": "directory--ff1e0780-358c-5808-a8c7-d0fca4ef6ef4",
          "path": "C:\\Windows\\System32",
          "path_enc": "bla.bla.bla"
        }
        self.assertFalseWithOptions(observed_data)

        observed_data['path_enc'] = "US-ASCII"
        self.assertTrueWithOptions(observed_data)

    def test_pdf_doc_info(self):
        observed_data = {
            "type": "file",
            "id": "file--ff1e0780-358c-5808-a8c7-d0fca4ef6ef4",
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
        observed_data = {
            "type": "software",
            "id": "software--ff1e0780-358c-5808-a8c7-d0fca4ef6ef4",
            "name": "word",
            "languages": ["bbb"]
        }
        self.assertFalseWithOptions(observed_data)

        observed_data['languages'][0] = 'eng'
        self.assertTrueWithOptions(observed_data)

    def test_software_cpe(self):
        observed_data = {
            "type": "software",
            "id": "software--ff1e0780-358c-5808-a8c7-d0fca4ef6ef4",
            "name": "word",
            "cpe": "invalid",
        }
        self.assertFalseWithOptions(observed_data)

        observed_data['cpe'] = 'cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*'
        self.assertTrueWithOptions(observed_data)

    def test_email_address_invalid_value(self):
        observed_data = {
            "type": "email-addr",
            "id": "email-addr--ff1e0780-358c-5808-a8c7-d0fca4ef6ef4",
            "value": "John Doe <jdoe@example.com>",
            "display_name": "John Doe"
        }
        self.assertFalseWithOptions(observed_data)

        observed_data['value'] = 'jdoe@example.com'
        self.assertTrueWithOptions(observed_data)

    def test_email_message_multipart(self):
        observed_data = {
            "type": "email-message",
            "id": "email-message--d3f4ef30-b14e-59c5-92d5-946e150e4ca3",
            "is_multipart": False,
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

        del observed_data['body_multipart']
        observed_data['body'] = "Hello World"
        self.assertTrueWithOptions(observed_data)

    def test_artifact_url_payloadbin(self):
        observed_data = {
            "type": "artifact",
            "id": "artifact--ff1e0780-358c-5808-a8c7-d0fca4ef6ef4",
            "mime_type": "image/jpeg",
            "payload_bin": "VBORw0KGgoAAAANSUhEUgAAADI==",
            "hashes": {
                "MD5": "69D0D97D02A03C43782DD571394E6869"
            },
            "url": "www.g.com"
        }
        self.assertFalseWithOptions(observed_data)

        del observed_data['url']
        self.assertTrueWithOptions(observed_data)

        observed_data['payload_bin'] = "failing test"
        self.assertFalseWithOptions(observed_data)

    def test_file_invalid_is_encrypted(self):
        observed_data = {
            "type": "artifact",
            "id": "artifact--ff1e0780-358c-5808-a8c7-d0fca4ef6ef4",
            "mime_type": "application/zip",
            "payload_bin": "VBORw0KGgoAAAANSUhEUgAAADI==",
            "decryption_key": "My voice is my passport"
        }
        self.assertFalseWithOptions(observed_data)

    def test_hash_length(self):
        observed_data = copy.deepcopy(self.valid_object)
        hash_name = "abcdefghijklmnopqrstuvwxyz0123456789"
        observed_data['hashes'][hash_name] = "8D98A25E9D0662B1F4CA3BF22D6F53E9"
        self.assertFalseWithOptions(observed_data)
        self.check_ignore(observed_data, ['hash-length', 'hash-algo'])

        observed_data = copy.deepcopy(self.valid_object)
        hash_name = "MD"
        observed_data['hashes'][hash_name] = "8D98A25E9D0662B1F4CA3BF22D6F53E9"
        self.assertFalseWithOptions(observed_data)

    def test_invalid_accessed_timestamp(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['created'] = "2016-11-31T08:17:27.000000Z"
        self.assertFalseWithOptions(observed_data)

        observed_data['created'] = "2016-04-06T19:58:16.000123Z"
        self.assertFalseWithOptions(observed_data)

        observed_data['modified'] = "2016-04-06T19:58:16.001Z"
        self.assertTrueWithOptions(observed_data)

    def test_invalid_extension_timestamp(self):
        observed_data = copy.deepcopy(self.valid_object)
        observed_data['extensions'] = {'windows-pebinary-ext': {
            "pe_type": "dll",
            "time_date_stamp": "2016-11-31T08:17:27Z",
        }}
        self.assertFalseWithOptions(observed_data)

    def test_invalid_observable_embedded_timestamp(self):
        observed_data = {
            "type": "x509-certificate",
            "id": "x509-certificate--ff1e0780-358c-5808-a8c7-d0fca4ef6ef4",
            "x509_v3_extensions": {
              "private_key_usage_period_not_before": "2016-11-31T08:17:27.000000Z"
            }
        }
        self.assertFalseWithOptions(observed_data)

    def test_additional_schemas_custom_extension_old_invalid_method(self):
        observed_data = copy.deepcopy(self.valid_object)
        observed_data['extensions'] = {'x-example-com-foobar-ext': {
            "foo_value": "something",
        }}
        self.assertFalseWithOptions(observed_data, schema_dir=self.custom_schemas)

    def test_additional_schemas_custom_extension(self):
        observed_data = copy.deepcopy(self.valid_object)
        observed_data['extensions'] = {'extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e': {
            "extension_type": "property-extension",
            "bar_value": "something",
        }}
        self.assertFalseWithOptions(observed_data, schema_dir=self.custom_schemas)

        observed_data['extensions']['extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e']['foo_value'] = 'something else'
        self.assertTrueWithOptions(observed_data, schema_dir=self.custom_schemas)

    def test_deprecated_objects_property(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        del observed_data['object_refs']
        observed_data['objects'] = {
            "windows-registry-key--ff1e0780-358c-5808-a8c7-d0fca4ef6ef4": {
                "type": "windows-registry-key",
                "id": "windows-registry-key--ff1e0780-358c-5808-a8c7-d0fca4ef6ef4",
                "key": "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\WSALG2"
            }
        }
        self.assertTrueWithOptions(observed_data, disabled="141,304")

    def test_invalid_objects_property(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        del observed_data['object_refs']
        observed_data['objects'] = [
            {
                "type": "windows-registry-key",
                "id": "windows-registry-key--ff1e0780-358c-5808-a8c7-d0fca4ef6ef4",
                "key": "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\WSALG2"
            }
            ]
        self.assertFalseWithOptions(observed_data)

    def test_url(self):
        observed_data = {
            "type": "url",
            "id": "url--ff1e0780-358c-5808-a8c7-d0fca4ef6ef4",
            "value": "foo",
        }
        self.assertFalseWithOptions(observed_data)

        observed_data['value'] = "http://www.example.com/file.txt"
        self.assertTrueWithOptions(observed_data)

    def test_url_in_artifact(self):
        observed_data = {
            "type": "artifact",
            "id": "artifact--ff1e0780-358c-5808-a8c7-d0fca4ef6ef4",
            "url": "foo",
            "hashes": {
                "MD5": "B4D33B0C7306351B9ED96578465C5579"
            },
            "mime_type": "text/plain"
        }
        self.assertFalseWithOptions(observed_data)

        observed_data['url'] = "http://www.example.com/file.txt"
        self.assertTrueWithOptions(observed_data)

    def test_invalid_seen_time(self):
        observed_data = copy.deepcopy(self.valid_observed_data)
        observed_data['first_observed'] = "2015-12-32T19:00:00Z"
        self.assertFalseWithOptions(observed_data)

        observed_data['first_observed'] = "2015-12-21T19:00:00.000123Z"
        self.assertFalseWithOptions(observed_data)

        observed_data['last_observed'] = "2015-12-21T19:00:00.001Z"
        self.assertTrueWithOptions(observed_data)

    def test_domain_name_not_deprecated_property(self):
        observed_data = {
            "type": "domain-name",
            "spec_version": "2.1",
            "id": "domain-name--ecb120bf-2694-5902-a737-62b74539a41b",
            "value": "example.com",
            "resolves_to_refs": ["ipv4-addr--efcd5e80-570d-4131-b213-62cb18eaa6a8"]
        }
        self.assertTrueWithOptions(observed_data)
