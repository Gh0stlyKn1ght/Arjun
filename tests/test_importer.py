import unittest

from arjun.core.importer import parse_request


class ImporterTests(unittest.TestCase):
    def test_parse_request_keeps_https_scheme_from_origin(self):
        request = parse_request(
            'POST /report HTTP/1.1\n'
            'Host: example.com\n'
            'Origin: https://example.com\n'
            '\n'
            '{"a":"b"}'
        )
        self.assertEqual(request['url'], 'https://example.com/report')

    def test_parse_request_keeps_absolute_url_scheme(self):
        request = parse_request(
            'POST https://example.com/report HTTP/1.1\n'
            'Host: example.com\n'
            '\n'
        )
        self.assertEqual(request['url'], 'https://example.com/report')

    def test_parse_request_handles_authority_form_targets(self):
        request = parse_request(
            'CONNECT example.com:443 HTTP/1.1\n'
            'Host: example.com\n'
            '\n'
        )
        self.assertEqual(request['url'], 'http://example.com:443')

    def test_forwarded_proto_is_detected_from_parameter_boundary(self):
        request = parse_request(
            'POST /report HTTP/1.1\n'
            'Host: example.com\n'
            'Forwarded: host=proto=https.example;for=1.1.1.1, proto=https\n'
            '\n'
        )
        self.assertEqual(request['url'], 'https://example.com/report')


if __name__ == '__main__':
    unittest.main()
