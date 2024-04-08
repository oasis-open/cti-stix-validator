import copy
import json

from . import ValidatorTest
from ... import validate_parsed_json, validate_string

VALID_TOOL = u"""
{
  "type": "tool",
  "id": "tool--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
  "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
  "created": "2016-04-06T20:03:48.000Z",
  "modified": "2016-04-06T20:03:48.000Z",
  "name": "VNC",
  "labels": ["remote-access"],
  "kill_chain_phases": [
    {
      "kill_chain_name": "lockheed-martin-cyber-kill-chain",
      "phase_name": "command-and-control"
    }
  ]
}
"""


class ToolTestCases(ValidatorTest):
    valid_tool = json.loads(VALID_TOOL)

    def test_wellformed_tool(self):
        results = validate_string(VALID_TOOL, self.options)
        self.assertTrue(results.is_valid)

    def test_invalid_timestamp(self):
        tool = copy.deepcopy(self.valid_tool)
        tool['created'] = "2016-11-31T01:00:00.000Z"
        self.assertFalseWithOptions(tool)

        tool['created'] = "2016-04-06T20:03:48.123Z"
        self.assertFalseWithOptions(tool)

        tool['modified'] = "2016-04-06T20:03:48.123Z"
        self.assertTrueWithOptions(tool)

    def test_vocab_tool_label(self):
        tool = copy.deepcopy(self.valid_tool)
        tool['labels'] += ["multi-purpose"]
        results = validate_parsed_json(tool, self.options)
        self.assertEqual(results.is_valid, False)

        self.check_ignore(tool, 'tool-label')

    def test_kill_chain_name(self):
        tool = copy.deepcopy(self.valid_tool)
        tool['kill_chain_phases'][0]['kill_chain_name'] = "Something"
        results = validate_parsed_json(tool, self.options)
        self.assertEqual(results.is_valid, False)

        tool['kill_chain_phases'][0]['kill_chain_name'] = "some thing"
        results = validate_parsed_json(tool, self.options)
        self.assertEqual(results.is_valid, False)

        tool['kill_chain_phases'][0]['kill_chain_name'] = "some_thing"
        results = validate_parsed_json(tool, self.options)
        self.assertEqual(results.is_valid, False)

        self.check_ignore(tool, 'kill-chain-names')

    def test_kill_chain_phase_name(self):
        tool = copy.deepcopy(self.valid_tool)
        tool['kill_chain_phases'][0]['phase_name'] = "Something"
        results = validate_parsed_json(tool, self.options)
        self.assertEqual(results.is_valid, False)

        tool['kill_chain_phases'][0]['phase_name'] = "some thing"
        results = validate_parsed_json(tool, self.options)
        self.assertEqual(results.is_valid, False)

        tool['kill_chain_phases'][0]['phase_name'] = "some_thing"
        results = validate_parsed_json(tool, self.options)
        self.assertEqual(results.is_valid, False)

        self.check_ignore(tool, 'kill-chain-names')

    def test_format_and_value_checks(self):
        tool = copy.deepcopy(self.valid_tool)
        tool['kill_chain_phases'][0]['phase_name'] = "Something_invalid"
        tool['labels'] += ["something-not-in-vocab"]

        self.assertFalseWithOptions(tool, disabled='1')
        self.assertFalseWithOptions(tool, disabled='2')
        self.assertTrueWithOptions(tool, disabled='1,2')
