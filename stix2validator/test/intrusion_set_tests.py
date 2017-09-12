import copy
import json
import unittest

from . import ValidatorTest
from .. import validate_instance, validate_string


VALID_INTRUSION_SET = """
{
  "type": "intrusion-set",
  "id": "intrusion-set--4e78f46f-a023-4e5f-bc24-71b3ca22ec29",
  "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
  "created": "2016-04-06T20:03:48.000Z",
  "modified": "2016-04-06T20:03:48.000Z",
  "name": "Bobcat Breakin",
  "description": "Incidents usually feature a shared TTP of a bobcat being released within the building containing network access, scaring users to leave their computers without locking them first. Still determining where the threat actors are getting the bobcats.",
  "aliases": ["Zookeeper"],
  "goals": ["acquisition-theft", "harassment", "damage"]
}
"""  # noqa


class IntrusionSetTestCases(ValidatorTest):
    valid_intrusion_set = json.loads(VALID_INTRUSION_SET)

    def test_wellformed_intrusion_set(self):
        results = validate_string(VALID_INTRUSION_SET, self.options)
        self.assertTrue(results.is_valid)

    def test_country(self):
        intrusion_set = copy.deepcopy(self.valid_intrusion_set)
        intrusion_set['country'] = "USA"
        results = validate_instance(intrusion_set, self.options)
        self.assertEqual(results.is_valid, False)

    def test_vocab_attack_motivation(self):
        intrusion_set = copy.deepcopy(self.valid_intrusion_set)
        intrusion_set['primary_motivation'] = "selfishness"
        results = validate_instance(intrusion_set, self.options)
        self.assertEqual(results.is_valid, False)

        self.check_ignore(intrusion_set, 'attack-motivation')

    def test_vocab_attack_resource_level(self):
        intrusion_set = copy.deepcopy(self.valid_intrusion_set)
        intrusion_set['resource_level'] = "high"
        results = validate_instance(intrusion_set, self.options)
        self.assertEqual(results.is_valid, False)

        self.check_ignore(intrusion_set, 'attack-resource-level')


if __name__ == "__main__":
    unittest.main()
