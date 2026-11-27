import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

from mcp_audit_security.core import Audit, triage_config
from mcp_audit_security import triage


def answer():
    return {'answers': {'verdict': {'type': 'choice', 'choice': 'webshell', 'confidence': .9},
                        'is_webshell': {'type': 'noul', 'noul': .8},
                        'risk_score': {'type': 'score', 'score': 1.9}}}


class TriageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.web = self.root / 'web'
        self.web.mkdir()
        self.key = self.root / 'key'
        self.key.write_text('KEY_DO_NOT_LEAK\n')
        self.key.chmod(0o600)
        self.cfg = triage_config({'model': 'typesafe/jev-1.14', 'api_key_file': str(self.key)})
        self.audit = Audit({'sites': {'demo': {'webroot': str(self.web)}}})
        (self.web / 'x.php').write_text('<?php DB_PASSWORD="SOURCE_SECRET"; eval($_POST["x"]);')

    def run_triage(self):
        return triage.Triage(self.audit, self.cfg).payload_triage('demo')

    def test_request_and_redaction(self):
        with patch.object(triage, 'post', return_value=answer()) as post:
            result = self.run_triage()
        self.assertEqual(result['items'][0]['verdict'], 'webshell')
        self.assertEqual(len(result['items'][0]['rules']), 3)
        url, key, body, timeout = post.call_args.args
        self.assertEqual(url, 'https://openrouter.ai/api/alpha/decisions')
        self.assertEqual(key, 'KEY_DO_NOT_LEAK')
        self.assertEqual(timeout, 30)
        self.assertEqual(set(body), {'model', 'state', 'questions', 'provider'})
        self.assertEqual(body['provider'], {'data_collection': 'deny', 'zdr': True})
        self.assertIn('<redacted>', body['state'])
        self.assertNotIn('SOURCE_SECRET', body['state'])
        self.assertNotIn('SOURCE_SECRET', json.dumps(result))
        self.assertNotIn('KEY_DO_NOT_LEAK', json.dumps(result))
        self.assertNotIn('<?php', json.dumps(result))

    def test_validation_and_refusal(self):
        cases = [None, {}, {'answers': None}, {'answers': {'verdict': {'type': 'refusal'}}}]
        for question, field, value in [('verdict', 'confidence', True), ('verdict', 'confidence', float('nan')),
                                       ('verdict', 'choice', 'SOURCE_SECRET'), ('is_webshell', 'noul', -1),
                                       ('risk_score', 'score', 3), ('risk_score', 'score', float('inf')),
                                       ('is_webshell', 'type', 'refusal'), ('risk_score', 'score', '1')]:
            data = answer()
            data['answers'][question][field] = value
            cases.append(data)
        for data in cases:
            with self.subTest(data=data), patch.object(triage, 'post', return_value=data):
                item = self.run_triage()['items'][0]
                self.assertEqual(item['verdict'], 'unanswered')
                self.assertIsNone(item['confidence'])
                self.assertIsNone(item['p_webshell'])
                self.assertIsNone(item['risk'])
        with patch.object(triage, 'post', return_value={'answers': {'verdict': {
                'type': 'choice', 'choice': 'suspicious'}}}):
            item = self.run_triage()['items'][0]
        self.assertEqual(item['verdict'], 'suspicious')
        self.assertIsNone(item['confidence'])

    def test_count_dedup_and_collect_before_network(self):
        (self.web / 'y.php').hardlink_to(self.web / 'x.php')
        (self.web / 'z.php').write_text('<?php system(1);')
        (self.web / 'a.php').write_text('<?php eval(2);')
        self.audit.config['sites']['demo']['files_dir'] = str(self.web)
        self.cfg['max_items'] = 10
        original = self.audit.collect
        collected = []
        def collect(*args):
            result = original(*args)
            collected.append(True)
            return result
        def post(*args):
            self.assertTrue(collected)
            return answer()
        with patch.object(self.audit, 'collect', side_effect=collect), patch.object(triage, 'post', side_effect=post) as stub:
            self.assertEqual(len(self.run_triage()['items']), 3)  # 6 matching paths, 3 unique hashes
            self.assertEqual(stub.call_count, 3)
            self.cfg['max_items'] = 2
            result = self.run_triage()
        self.assertEqual(len(result['items']), 2)
        self.assertEqual(stub.call_count, 5)
        self.assertTrue(result['truncated'])
        self.assertEqual(result['max_items'], 2)

    def test_whole_file_limit(self):
        self.cfg['max_file_bytes'] = 8
        with patch.object(triage, 'post') as stub:
            result = self.run_triage()
        stub.assert_not_called()
        self.assertTrue(result['truncated'])
        self.assertIn('triage_file_byte_limit', result['errors'])

    def test_key_failures(self):
        for kind in ('missing', 'empty', 'symlink', 'permissions', 'large', 'newline'):
            with self.subTest(kind=kind):
                path = self.root / kind
                if kind == 'symlink':
                    path.symlink_to(self.key)
                elif kind != 'missing':
                    path.write_text({'empty': '', 'permissions': 'KEY', 'large': 'x' * 8193,
                                     'newline': 'KEY\nBAD'}.get(kind, 'KEY'))
                    path.chmod(0o644 if kind == 'permissions' else 0o600)
                self.cfg['api_key_file'] = str(path)
                with patch.object(triage, 'post') as stub:
                    result = self.run_triage()
                self.assertEqual(result['errors'], ['api_key_unavailable'])
                stub.assert_not_called()

    def test_http_and_other_errors_sanitized(self):
        for exc, code in [(urllib.error.HTTPError('secret', 429, 'SOURCE_SECRET', {}, io.BytesIO(b'SOURCE_SECRET')), 'http_429'),
                          (TimeoutError('KEY_DO_NOT_LEAK'), 'request_timeout'),
                          (ValueError('SOURCE_SECRET'), 'invalid_response')]:
            with patch.object(triage, 'post', side_effect=exc):
                result = self.run_triage()
            self.assertIn(code, result['errors'])
            self.assertNotIn('SOURCE_SECRET', json.dumps(result))
            self.assertNotIn('KEY_DO_NOT_LEAK', json.dumps(result))
            self.assertEqual(result['items'][0]['verdict'], 'unanswered')

    def test_transport_bounded_and_redirect_blocked(self):
        handler = triage.NoRedirect()
        self.assertIsNone(handler.redirect_request(None, None, 302, '', {}, 'https://evil.invalid'))
        response = unittest.mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b'x' * (triage.MAX_RESPONSE + 1)
        opener = unittest.mock.Mock()
        opener.open.return_value = response
        with patch.object(triage.urllib.request, 'build_opener', return_value=opener):
            with self.assertRaises(ValueError):
                triage.post(triage.URL, 'key', {}, 2)
        self.assertEqual(response.read.call_args.args, (triage.MAX_RESPONSE + 1,))
        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_header('Authorization'), 'Bearer key')
        self.assertEqual(opener.open.call_args.kwargs['timeout'], 2)


if __name__ == '__main__':
    unittest.main()
