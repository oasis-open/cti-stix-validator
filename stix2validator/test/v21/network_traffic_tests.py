import copy
import json

from . import ValidatorTest
from ... import validate_string

VALID_NETWORK_TRAFFIC_DEFINITION = u"""
  {
    "type": "network-traffic",
    "id" : "network-traffic--280d1c0d-51d1-5ee8-951f-1fb434a38686",
    "src_ref": "ipv4-addr--e42c19c8-f9fe-5ae9-9fc8-22c398f78fb",
    "src_port": 24678,
    "dst_port": 80,
    "protocols": [
    "ipv4",
    "tcp"
    ],
    "src_byte_count": 147600,
    "src_packets": 100
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
        del net_traffic['src_ref']
        self.assertFalseWithOptions(net_traffic)

        net_traffic = copy.deepcopy(self.valid_net_traffic)
        del net_traffic['protocols']
        self.assertFalseWithOptions(net_traffic)

    def test_network_traffic_ports(self):
        net_traffic = copy.deepcopy(self.valid_net_traffic)
        del net_traffic['src_port']
        del net_traffic['dst_port']
        self.assertFalseWithOptions(net_traffic)

        net_traffic['src_port'] = 3372
        self.assertFalseWithOptions(net_traffic)

        self.check_ignore(net_traffic, 'network-traffic-ports')

        net_traffic['dst_port'] = 80
        self.assertTrueWithOptions(net_traffic)

        net_traffic['src_port'] = 9999999
        self.assertFalseWithOptions(net_traffic)

    def test_network_traffic_protocols(self):
        net_traffic = copy.deepcopy(self.valid_net_traffic)
        net_traffic['protocols'].append('foo_bar')
        self.assertFalseWithOptions(net_traffic)
        self.check_ignore(net_traffic, 'protocols')

        net_traffic['protocols'][2] = 'https'
        self.assertTrueWithOptions(net_traffic)

    def test_network_traffic_ipfix(self):
        net_traffic = copy.deepcopy(self.valid_net_traffic)
        net_traffic['ipfix'] = {
            "minimumIpTotalLength": 32,
            "maximumIpTotalLength": 2556,
            "Foo": "bar"
        }
        self.assertFalseWithOptions(net_traffic)
        self.check_ignore(net_traffic, 'ipfix')

    def test_network_traffic_http_request_header(self):
        net_traffic = copy.deepcopy(self.valid_net_traffic)
        net_traffic['extensions'] = {
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
        net_traffic['extensions'] = {
            "socket-ext": {
                "address_family": "AF_INET",
                "socket_type": "SOCK_STREAM",
                "options": {
                    "SO_TEST": 1000,
                    "IP_TEST": 100,
                    "MCAST_TEST": 10
                }
            }
        }
        self.assertFalseWithOptions(net_traffic)
        self.check_ignore(net_traffic, 'socket-options')

    def test_network_traffic_end_is_active(self):
        net_traffic = copy.deepcopy(self.valid_net_traffic)
        net_traffic['is_active'] = True
        net_traffic['end'] = "2016-12-21T19:00:00Z"
        self.assertFalseWithOptions(net_traffic)

        del net_traffic['end']
        self.assertTrueWithOptions(net_traffic)

    def test_invalid_start_end_time(self):
        net_traffic = copy.deepcopy(self.valid_net_traffic)
        net_traffic['start'] = "2016-04-31T20:06:37.000Z"
        net_traffic['end'] = "2016-04-06T20:06:37.000Z"
        self.assertFalseWithOptions(net_traffic)

        net_traffic['start'] = "2016-04-06T20:06:37.000123Z"
        self.assertFalseWithOptions(net_traffic)

        net_traffic['end'] = "2016-04-06T20:06:37.001Z"
        self.assertTrueWithOptions(net_traffic)
