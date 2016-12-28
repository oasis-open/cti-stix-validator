import unittest
import copy
import json
from . import ValidatorTest
from .. import validate_string

VALID_TOOL = """
{
  "type": "tool",
  "id": "tool--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
  "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
  "created": "2016-04-06T20:03:48Z",
  "modified": "2016-04-06T20:03:48Z",
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

    def test_vocab_tool_label(self):
        tool = copy.deepcopy(self.valid_tool)
        tool['labels'] += ["multi-purpose"]
        tool = json.dumps(tool)
        results = validate_string(tool, self.options)
        self.assertEqual(results.is_valid, False)

        self.check_ignore(tool, 'tool-label')

    def test_kill_chain_name(self):
        tool = copy.deepcopy(self.valid_tool)
        tool['kill_chain_phases'][0]['kill_chain_name'] = "Something"
        tool_string = json.dumps(tool)
        results = validate_string(tool_string, self.options)
        self.assertEqual(results.is_valid, False)

        tool['kill_chain_phases'][0]['kill_chain_name'] = "some thing"
        tool_string = json.dumps(tool)
        results = validate_string(tool_string, self.options)
        self.assertEqual(results.is_valid, False)

        tool['kill_chain_phases'][0]['kill_chain_name'] = "some_thing"
        tool_string = json.dumps(tool)
        results = validate_string(tool_string, self.options)
        self.assertEqual(results.is_valid, False)

        self.check_ignore(tool_string, 'kill-chain-names')

    def test_kill_chain_phase_name(self):
        tool = copy.deepcopy(self.valid_tool)
        tool['kill_chain_phases'][0]['phase_name'] = "Something"
        tool_string = json.dumps(tool)
        results = validate_string(tool_string, self.options)
        self.assertEqual(results.is_valid, False)

        tool['kill_chain_phases'][0]['phase_name'] = "some thing"
        tool_string = json.dumps(tool)
        results = validate_string(tool_string, self.options)
        self.assertEqual(results.is_valid, False)

        tool['kill_chain_phases'][0]['phase_name'] = "some_thing"
        tool_string = json.dumps(tool)
        results = validate_string(tool_string, self.options)
        self.assertEqual(results.is_valid, False)

        self.check_ignore(tool_string, 'kill-chain-names')

    def test_format_and_value_checks(self):
        tool = copy.deepcopy(self.valid_tool)
        tool['kill_chain_phases'][0]['phase_name'] = "Something_invalid"
        tool['labels'] += ["something-not-in-vocab"]
        tool_string = json.dumps(tool)

        self.assertFalseWithOptions(tool_string, disabled='1')
        self.assertFalseWithOptions(tool_string, disabled='2')
        self.assertTrueWithOptions(tool_string, disabled='1,2')


if __name__ == "__main__":
    unittest.main()
