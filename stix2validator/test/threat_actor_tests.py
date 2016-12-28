import unittest
import copy
import json
from . import ValidatorTest
from .. import validate_string

VALID_THREAT_ACTOR = """
{
  "type": "threat-actor",
  "id": "threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
  "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
  "created": "2016-04-06T20:03:48Z",
  "modified": "2016-04-06T20:03:48Z",
  "labels": ["hacker"],
  "name": "Evil Org",
  "description": "The Evil Org threat actor group"
}
"""


class ThreatActorTestCases(ValidatorTest):
    valid_threat_actor = json.loads(VALID_THREAT_ACTOR)

    def test_wellformed_threat_actor(self):
        results = validate_string(VALID_THREAT_ACTOR, self.options)
        self.assertTrue(results.is_valid)

    def test_vocab_attack_motivation(self):
        threat_actor = copy.deepcopy(self.valid_threat_actor)
        threat_actor['primary_motivation'] = "selfishness"
        threat_actor = json.dumps(threat_actor)
        results = validate_string(threat_actor, self.options)
        self.assertEqual(results.is_valid, False)

        self.check_ignore(threat_actor, 'attack-motivation')

    def test_vocab_attack_resource_level(self):
        threat_actor = copy.deepcopy(self.valid_threat_actor)
        threat_actor['resource_level'] = "high"
        threat_actor = json.dumps(threat_actor)
        results = validate_string(threat_actor, self.options)
        self.assertEqual(results.is_valid, False)

        self.check_ignore(threat_actor, 'attack-resource-level')

    def test_vocab_threat_actor_label(self):
        threat_actor = copy.deepcopy(self.valid_threat_actor)
        threat_actor['labels'] += ["anonymous"]
        threat_actor = json.dumps(threat_actor)
        results = validate_string(threat_actor, self.options)
        self.assertEqual(results.is_valid, False)

        self.check_ignore(threat_actor, 'threat-actor-label')

    def test_vocab_threat_actor_role(self):
        threat_actor = copy.deepcopy(self.valid_threat_actor)
        threat_actor['roles'] = ["contributor"]
        threat_actor = json.dumps(threat_actor)
        results = validate_string(threat_actor, self.options)
        self.assertEqual(results.is_valid, False)

        self.check_ignore(threat_actor, 'threat-actor-role')

    def test_vocab_threat_actor_sophistication_level(self):
        threat_actor = copy.deepcopy(self.valid_threat_actor)
        threat_actor['sophistication'] = "high"
        threat_actor = json.dumps(threat_actor)
        results = validate_string(threat_actor, self.options)
        self.assertEqual(results.is_valid, False)

        self.check_ignore(threat_actor,
                          'threat-actor-sophistication')


if __name__ == "__main__":
    unittest.main()
