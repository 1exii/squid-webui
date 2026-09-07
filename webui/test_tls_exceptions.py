import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from tls_exceptions import DEFAULT_EXCEPTIONS, validate_exceptions, render_exceptions


class ExceptionRulesTests(unittest.TestCase):
    def test_validation_rejects_injection_and_non_public_destinations(self):
        for domain in ['*.vivox.com', 'vivox.com\nssl_bump splice all', 'https://vivox.com', '1.2.3.4']:
            with self.assertRaises(ValueError):
                validate_exceptions([dict(domain=domain, enabled=True, destination_networks=[])])
        for network in ['0.0.0.0/0', '192.168.1.0/24', '85.236.98.25/21', '85.236.98.25\nall']:
            with self.assertRaises(ValueError):
                validate_exceptions([dict(domain='vivox.com', enabled=True, destination_networks=[network])])

    def test_disabled_deleted_and_normalized_entries(self):
        entry = dict(domain='ViVoX.COM.', enabled=False, destination_networks=[])
        self.assertEqual(validate_exceptions([entry])[0]['domain'], 'vivox.com')
        self.assertNotIn('ssl_bump splice', render_exceptions([entry]))
        self.assertNotIn('ssl_bump splice', render_exceptions([]))
        with self.assertRaises(ValueError):
            validate_exceptions([entry, entry])

    def test_explicit_domains_do_not_reverse_resolve_transparent_ips(self):
        rules = render_exceptions(DEFAULT_EXCEPTIONS)
        self.assertIn('dstdomain -n .vivox.com', rules)
        self.assertIn('tls_exception_explicit tls_exception_0_domain', rules)
        self.assertIn('dst 85.236.104.0/23 85.236.96.0/21', rules)
        for line in rules.splitlines():
            if line.startswith('ssl_bump'):
                self.assertIn('splice tls_exception_step1 tls_exception_https', line)
        template = (Path(__file__).parent.parent / 'configs/squid.conf.template').read_text()
        self.assertLess(template.index('include /etc/squid/configs/early_splice.acl'), template.index('ssl_bump peek step1'))


try:
    import app as app_module
except ModuleNotFoundError:
    app_module = None


@unittest.skipIf(app_module is None, 'WebUI dependencies unavailable')
class ExceptionApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.patches = []
        for name, filename in [('SQUID_CONFIG_DIR', ''), ('TLS_EXCEPTIONS_PATH', 'tls_exceptions.json'),
                               ('EARLY_SPLICE_PATH', 'early_splice.acl'), ('RULES_ACL_PATH', 'rules.acl'),
                               ('SSL_BUMP_ACL_PATH', 'ssl_bump.acl'), ('SQUID_AUDIT_LOG', 'audit.jsonl')]:
            self.patches.append(patch.object(app_module, name, os.path.join(self.tmp.name, filename)))
        for p in self.patches: p.start()
        self.managed = patch.object(app_module, '_MANAGED_CONFIG_FILES', (app_module.TLS_EXCEPTIONS_PATH,
            app_module.EARLY_SPLICE_PATH, app_module.RULES_ACL_PATH, app_module.SSL_BUMP_ACL_PATH))
        self.managed.start()
        self.client = app_module.app.test_client()
        self.client.environ_base['REMOTE_ADDR'] = '203.0.113.12'

    def tearDown(self):
        self.managed.stop()
        for p in reversed(self.patches): p.stop()
        self.tmp.cleanup()

    def auth(self):
        with self.client.session_transaction() as session:
            session['authenticated'] = True

    def test_auth_and_validation(self):
        self.assertEqual(self.client.get('/api/tls-exceptions').status_code, 401)
        self.assertEqual(self.client.post('/api/tls-exceptions', json={'entries': []}).status_code, 401)
        self.auth()
        self.assertEqual(self.client.post('/api/tls-exceptions', json={'entries': 'bad'}).status_code, 400)

    def test_first_failed_compile_restores_missing_json_and_empty_include(self):
        with patch.object(app_module, 'get_parsed_blocklists', side_effect=ValueError('bad list')):
            self.assertFalse(app_module.compile_device_policies_acls({})[0])
        self.assertFalse(Path(app_module.TLS_EXCEPTIONS_PATH).exists())
        self.assertNotIn('ssl_bump splice', Path(app_module.EARLY_SPLICE_PATH).read_text())

    def test_editor_is_rendered_only_on_admin_surface(self):
        self.assertNotIn(b'id="tls-exceptions-panel"', self.client.get('/').data)
        self.assertIn(b'id="tls-exceptions-panel"', self.client.get('/admin').data)

    def test_save_survives_policy_compile_and_failed_save_rolls_back(self):
        self.auth()
        entry = dict(domain='voice.example.com', enabled=True, destination_networks=[])
        with patch.object(app_module, 'get_parsed_blocklists', return_value={}), \
             patch.object(app_module, 'write_bump_domains'), \
             patch.object(app_module, 'load_device_policies', return_value={}), \
             patch.object(app_module, 'reload_squid', return_value=(True, 'ok')):
            response = self.client.post('/api/tls-exceptions', json={'entries': [entry]})
            self.assertEqual(response.status_code, 200, response.json)
            self.assertTrue(app_module.compile_device_policies_acls({})[0])
            self.assertEqual(app_module.load_tls_exceptions(), [entry])
            original = Path(app_module.EARLY_SPLICE_PATH).read_text()
            with patch.object(app_module, 'reload_squid', return_value=(False, 'parse failed')):
                response = self.client.post('/api/tls-exceptions', json={'entries': []})
            self.assertEqual(response.status_code, 500)
            self.assertEqual(app_module.load_tls_exceptions(), [entry])
            self.assertEqual(Path(app_module.EARLY_SPLICE_PATH).read_text(), original)
            self.assertIn('tls_exceptions_changed', Path(app_module.SQUID_AUDIT_LOG).read_text())


if __name__ == '__main__':
    unittest.main()
