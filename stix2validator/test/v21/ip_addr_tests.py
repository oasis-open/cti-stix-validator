import copy
import json

from . import ValidatorTest
from ... import validate_string

VALID_IPV4 = u"""
{
 "type": "ipv4-addr",
 "spec_version": "2.1",
 "id": "ipv4-addr--ff26c055-6336-5bc5-b98d-13d6226742dd",
 "value": "198.51.100.3"
}
"""

VALID_IPV6 = u"""
{
 "type": "ipv6-addr",
 "spec_version": "2.1",
 "id": "ipv6-addr--1e61d36c-a16c-53b7-a80f-2a00161c96b1",
 "value": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
}
"""


class IPv4TestCases(ValidatorTest):
    valid_ipv4 = json.loads(VALID_IPV4)

    def test_wellformed_ipv4_addr(self):
        results = validate_string(VALID_IPV4, self.options)
        self.assertTrue(results.is_valid)

    def test_valid_ipv4(self):
        values = [
            "192.168.0.1",
            "192.168.0.1/0",
            "192.168.0.1/5",
            "192.168.0.1/32",
        ]
        ipv4 = copy.deepcopy(self.valid_ipv4)
        for value in values:
            ipv4['value'] = value
            self.assertTrueWithOptions(ipv4)

    def test_invalid_ipv4(self):
        values = [
            "foo",
            "999.999.999.999",
            "192.168.0.1/",
            "192.168.0.1/33",
            "192.168.0.1/a",
            "192.168.0.1/01",
        ]
        ipv4 = copy.deepcopy(self.valid_ipv4)
        for value in values:
            ipv4['value'] = value
            self.assertFalseWithOptions(ipv4)


class IPv6TestCases(ValidatorTest):
    valid_ipv6 = json.loads(VALID_IPV6)

    def test_wellformed_ipv6_addr(self):
        results = validate_string(VALID_IPV6, self.options)
        self.assertTrue(results.is_valid)

    def test_valid_ipv6(self):
        values = [
            "fe80:0000:0000:0000:0204:61ff:fe9d:f156",
            "fe80:0000:0000:0000:0204:61ff:fe9d:f156/0",
            "fe80:0000:0000:0000:0204:61ff:fe9d:f156/6",
            "fe80:0000:0000:0000:0204:61ff:fe9d:f156/128",
        ]
        ipv6 = copy.deepcopy(self.valid_ipv6)
        for value in values:
            ipv6['value'] = value
            self.assertTrueWithOptions(ipv6)

    def test_invalid_ipv6(self):
        values = [
            "foo",
            "fe80:0000:0000:0000:0204:61ff:fe9d:f156/",
            "fe80:0000:0000:0000:0204:61ff:fe9d:f156/129",
            "fe80:0000:0000:0000:0204:61ff:fe9d:f156/a",
            "fe80:0000:0000:0000:0204:61ff:fe9d:f156/00",
            "fe80:0000:0000:0000:0204:61ff:fe9d:f156/03",
        ]
        ipv6 = copy.deepcopy(self.valid_ipv6)
        for value in values:
            ipv6['value'] = value
            self.assertFalseWithOptions(ipv6)
