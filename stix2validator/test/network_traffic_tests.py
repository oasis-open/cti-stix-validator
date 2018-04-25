import copy
import json

from . import ValidatorTest
from .. import validate_string

VALID_NETWORK_TRAFFIC_DEFINITION = u"""
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
      "type": "ipv4-addr",
      "value": "203.0.113.5"
    },
    "1": {
      "type": "network-traffic",
      "src_ref": "0",
      "src_port": 24678,
      "dst_port": 80,
      "protocols": [
        "ipv4",
        "tcp"
      ],
      "src_byte_count": 147600,
      "src_packets": 100
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
    valid_net_traffic = json.loads(VALID_NETWORK_TRAFFIC_DEFINITION)

    def test_wellformed_network_traffic(self):
        results = validate_string(VALID_NETWORK_TRAFFIC_DEFINITION,
                                  self.options)
        self.assertTrue(results.is_valid)

    def test_network_traffic_required_fields(self):
        net_traffic = copy.deepcopy(self.valid_net_traffic)
        del net_traffic['objects']['1']['src_ref']
        self.assertFalseWithOptions(net_traffic)

        net_traffic = copy.deepcopy(self.valid_net_traffic)
        del net_traffic['objects']['1']['protocols']
        self.assertFalseWithOptions(net_traffic)

    def test_network_traffic_ports(self):
        net_traffic = copy.deepcopy(self.valid_net_traffic)
        del net_traffic['objects']['1']['src_port']
        del net_traffic['objects']['1']['dst_port']
        self.assertFalseWithOptions(net_traffic)

        net_traffic['objects']['1']['src_port'] = 3372
        self.assertFalseWithOptions(net_traffic)

        self.check_ignore(net_traffic, 'network-traffic-ports')

        net_traffic['objects']['1']['dst_port'] = 80
        self.assertTrueWithOptions(net_traffic)

        net_traffic['objects']['1']['src_port'] = 9999999
        self.assertFalseWithOptions(net_traffic)

    def test_network_traffic_protocols(self):
        net_traffic = copy.deepcopy(self.valid_net_traffic)
        net_traffic['objects']['1']['protocols'].append('foo_bar')
        self.assertFalseWithOptions(net_traffic)
        self.check_ignore(net_traffic, 'protocols')

        net_traffic['objects']['1']['protocols'][2] = 'https'
        self.assertTrueWithOptions(net_traffic)

    def test_network_traffic_ipfix(self):
        net_traffic = copy.deepcopy(self.valid_net_traffic)
        net_traffic['objects']['1']['ipfix'] = {
            "minimumIpTotalLength": 32,
            "maximumIpTotalLength": 2556,
            "Foo": "bar"
        }
        self.assertFalseWithOptions(net_traffic)
        self.check_ignore(net_traffic, 'ipfix')

    def test_network_traffic_http_request_header(self):
        net_traffic = copy.deepcopy(self.valid_net_traffic)
        net_traffic['objects']['1']['extensions'] = {
            "http-request-ext": {
                "request_method": "get",
                "request_value": "/download.html",
                "request_version": "http/1.1",
                "request_header": {
                    "Accept-Encoding": "gzip,deflate",
                    "Host": "www.example.com",
                    "x-foobar": "something"
                }
            }
        }
        self.assertFalseWithOptions(net_traffic)
        self.check_ignore(net_traffic, 'http-request-headers')

    def test_network_traffic_socket_options(self):
        net_traffic = copy.deepcopy(self.valid_net_traffic)
        net_traffic['objects']['1']['extensions'] = {
            "socket-ext": {
                "address_family": "AF_INET",
                "socket_type": "SOCK_STREAM",
                "options": {
                    "foo": "bar"
                }
            }
        }
        self.assertFalseWithOptions(net_traffic)
        self.check_ignore(net_traffic, 'socket-options')

    def test_network_traffic_end_is_active(self):
        net_traffic = copy.deepcopy(self.valid_net_traffic)
        net_traffic['objects']['1']['is_active'] = True
        net_traffic['objects']['1']['end'] = "2016-12-21T19:00:00Z"
        self.assertFalseWithOptions(net_traffic)

        del net_traffic['objects']['1']['end']
        self.assertTrueWithOptions(net_traffic)
