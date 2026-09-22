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


if __name__ == '__main__':
    unittest.main()
