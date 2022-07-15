from . import ValidatorTest
from ... import ValidationOptions, validate_string

OBJECT_MARKING_FAILURE = u"""
{
    "type": "campaign",
    "spec_version": "2.1",
    "id": "campaign--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
    "created": "2016-05-12T08:17:27.000Z",
    "modified": "2016-05-12T08:17:27.000Z",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "name": "Spear Phishing",
    "external_references": [
        {
            "source_name": "capec",
            "external_id": "CAPEC-163"
        }
    ],
    "kill_chain_phases":
      [
        {
        "kill_chain_name": "example-kill-chain",
        "phase_name": "lateral-movement"
        }
      ],
      "object_marking_refs": [
        "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
        "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"
      ]
  }
  """


OBJECT_MARKINGS_SUCCESS = u"""
{
    "type": "campaign",
    "spec_version": "2.1",
    "id": "campaign--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
    "created": "2016-05-12T08:17:27.000Z",
    "modified": "2016-05-12T08:17:27.000Z",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "name": "Spear Phishing",
    "external_references": [
        {
            "source_name": "capec",
            "external_id": "CAPEC-163"
        }
    ],
    "kill_chain_phases":
      [
        {
        "kill_chain_name": "example-kill-chain",
        "phase_name": "lateral-movement"
        }
      ],
      "object_marking_refs": [
        "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
        "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ef"
      ]
  }
  """

NON_INTEROP_STIX = u"""
{
    "type": "campaign",
    "spec_version": "2.1",
    "id": "campaign--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
    "created": "2016-05-12T08:17:27.000Z",
    "modified": "2016-05-12T08:17:27.000Z",
    "name": "Spear Phishing"
}
"""
INTEROP_STIX = u"""
{
    "type": "campaign",
    "spec_version": "2.1",
    "id": "campaign--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
    "created": "2016-05-12T08:17:27.000Z",
    "modified": "2016-05-12T08:17:27.000Z",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "name": "Spear Phishing"
}
"""


class InteropTestCases(ValidatorTest):
    def test_obj_markings_invalid(self):
        options = ValidationOptions(interop=True, version="2.1")
        results = validate_string(OBJECT_MARKING_FAILURE, options)
        self.assertFalse(results.is_valid)

    def test_obj_markings_valid(self):
        options = ValidationOptions(interop=True, version="2.1")
        results = validate_string(OBJECT_MARKINGS_SUCCESS, options)
        self.assertTrue(results.is_valid)

    def test_interop_sro_specifics_Compliant(self):
        options = ValidationOptions(interop=True, version="2.1")
        results = validate_string(INTEROP_STIX, options)
        self.assertTrue(results.is_valid)

    def test_interop_sro_specifics_Non_Compliant(self):
        options = ValidationOptions(interop=True, version="2.1")
        results = validate_string(NON_INTEROP_STIX, options)
        self.assertFalse(results.is_valid)
