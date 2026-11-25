import json
import os
from pathlib import Path
import tempfile
import unittest

from mcp_audit_security.core import Audit, load_config, ConfigError


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.web = self.root / 'web'
        self.web.mkdir()
        self.config = self.root / 'config.json'
        self.config.write_text(json.dumps({'sites': {'demo': {'webroot': str(self.web)}}}))

    def test_config_and_inventory(self):
        (self.web / 'index.php').write_text('<?php echo 1;')
        audit = Audit(load_config(str(self.config)))
        result = audit.web_integrity('demo')
        self.assertEqual(result['items'][0]['size'], 13)
        self.assertEqual(len(result['items'][0]['sha256']), 64)
        self.assertNotIn('echo', json.dumps(result))
        with self.assertRaises(ValueError):
            audit.web_integrity('../demo')

    def test_payload_and_symlinks(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / 'secret').write_text('SECRET_OUTSIDE <?php eval($_POST["x"]);')
        (self.web / 'escape').symlink_to(outside, target_is_directory=True)
        (self.web / 'file-link').symlink_to(outside / 'secret')
        (self.web / 'photo.jpg').write_text('<?php\neval(base64_decode($_POST["SECRET_VALUE"]));')
        result = Audit(load_config(str(self.config))).payload_scan('demo')
        self.assertTrue(any(i['rule_id'] == 'PHP_DYNAMIC_EXEC' for i in result['items']))
        self.assertTrue(any(i['rule_id'] == 'PHP_TAG' for i in result['items']))
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertTrue(result['errors'])
        self.assertTrue(all(i['path'] == 'webroot/photo.jpg' for i in result['items']))

    def test_logs_metadata_only(self):
        log = self.root / 'access.log'
        log.write_text('127.0.0.1 - - [25/Nov/2026:01:02:03 +0000] "GET /x?password=SECRET HTTP/1.1" 403 123 "SECRET" "SECRET"\ninvalid SECRET\n')
        config = load_config(str(self.config))
        config['sites']['demo']['logs'] = {'access': str(log)}
        audit = Audit(config)
        result = audit.log_timeline('demo', 'access')
        self.assertEqual(result['items'][0]['status'], 403)
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertNotIn('/x', json.dumps(result))
        with self.assertRaises(ValueError):
            audit.log_timeline('demo', '../access')

    def test_inventory_and_persistence(self):
        audit = Audit(load_config(str(self.config)))
        host = audit.host_inventory()
        self.assertIn('kernel', host)
        self.assertNotIn('environ', json.dumps(host))
        # Use inert persistence roots; never scan real system in unit tests.
        from unittest.mock import patch
        with patch('mcp_audit_security.core.PERSISTENCE', (('fixture', str(self.web)),)), patch('mcp_audit_security.core.PASSWD', str(self.root / 'passwd')):
            (self.web / 'cron').write_text('password=SECRET')
            (self.root / 'passwd').write_text('alice:SECRET:1000:1000:SECRET:/home/alice:/bin/bash\n')
            result = audit.persistence_audit()
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertEqual(result['accounts'][0]['uid'], 1000)

    def test_bounds_and_baseline(self):
        from unittest.mock import patch
        import hashlib
        (self.web / 'a').write_text('ok')
        manifest = self.root / 'baseline.json'
        manifest.write_text(json.dumps({'webroot/a': hashlib.sha256(b'ok').hexdigest(), 'webroot/missing': '0' * 64}))
        config = load_config(str(self.config))
        config['sites']['demo']['manifest'] = str(manifest)
        result = Audit(config).web_integrity('demo')
        self.assertEqual(result['items'][0]['baseline'], 'match')
        self.assertEqual(result['missing'], ['webroot/missing'])
        for i in range(5):
            (self.web / str(i)).write_text('<?php eval(1);')
        with patch('mcp_audit_security.core.MAX_RESULTS', 2):
            result = Audit(config).payload_scan('demo')
            self.assertLessEqual(len(result['items']), 2)
            self.assertTrue(result['truncated'])
        with patch('mcp_audit_security.core.MAX_FILES', 2):
            result = Audit(config).web_integrity('demo')
            self.assertLessEqual(result['entries_examined'], 2)
            self.assertTrue(result['truncated'])
        with patch('mcp_audit_security.core.MAX_FILE', 1):
            result = Audit(config).payload_scan('demo')
            self.assertTrue(result['truncated'])
            self.assertIn('file_byte_limit', result['errors'])
        with patch('mcp_audit_security.core.MAX_SECONDS', 0):
            self.assertTrue(Audit(config).payload_scan('demo')['truncated'])

    def test_files_dir_log_limit_and_root_escape(self):
        from unittest.mock import patch
        files = self.root / 'private-files'
        files.mkdir()
        (files / 'upload.dat').write_text('<?php system(1);')
        log = self.root / 'access.log'
        log.write_text(('127.0.0.1 - - [25/Nov/2026:01:02:03 +0000] "GET /?secret=SECRET HTTP/1.1" 200 1\n') * 100)
        config = load_config(str(self.config))
        config['sites']['demo'].update(files_dir=str(files), logs={'access': str(log)})
        audit = Audit(config)
        self.assertTrue(any(x['path'] == 'files_dir/upload.dat' for x in audit.payload_scan('demo')['items']))
        with patch('mcp_audit_security.core.MAX_LOG_BYTES', 200):
            result = audit.log_timeline('demo', 'access')
            self.assertTrue(result['truncated'])
            self.assertLessEqual(result['bytes_read'], 200)
            self.assertNotIn('SECRET', json.dumps(result))
        link = self.root / 'web-link'
        link.symlink_to(files, target_is_directory=True)
        config['sites']['demo']['webroot'] = str(link)
        config['sites']['demo'].pop('files_dir')
        result = Audit(config).payload_scan('demo')
        self.assertFalse(result['items'])
        self.assertIn('root_inaccessible_or_unsafe', result['errors'])

    def test_config_symlinks_and_duplicates(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ConfigError):
            load_config(str(alias / 'config.json'))
        self.config.write_text('{"sites":{},"sites":{}}')
        with self.assertRaises(ConfigError):
            load_config(str(self.config))
        self.config.write_text('[]')
        with self.assertRaises(ConfigError):
            load_config(str(self.config))

    def test_command_failure_not_empty_success(self):
        from unittest.mock import patch
        import sys
        from mcp_audit_security.core import fixed_command
        args = ('python-fixture', '-c', 'raise SystemExit(3)')
        real_spawn = __import__('subprocess').Popen
        with patch('mcp_audit_security.core.COMMANDS', {args}), \
             patch('mcp_audit_security.core.os.path.isfile', return_value=True), \
             patch('mcp_audit_security.core.subprocess.Popen') as spawn:
            def start(argv, **kwargs):
                return real_spawn([sys.executable, *argv[1:]], **kwargs)
            spawn.side_effect = start
            with self.assertRaises(OSError):
                fixed_command(args)

    def test_invalid_config(self):
        for value in ({}, {'sites': {}}, {'sites': {'x': {'webroot': '../bad'}}},
                      {'sites': {'x': {'webroot': '/', 'unknown': 1}}}):
            self.config.write_text(json.dumps(value))
            with self.assertRaises(ConfigError):
                load_config(str(self.config))
        with self.assertRaises(ConfigError):
            load_config(None)


if __name__ == '__main__':
    unittest.main()
