#!/usr/bin/env python3
"""Safety checks for an installer that writes system configuration; no host mutations."""
import importlib.util
import os
import hashlib
import io
import subprocess
import sys
import tarfile
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('installer', ROOT / 'scripts/install-controller.py')
i = importlib.util.module_from_spec(spec); spec.loader.exec_module(i)

class Installer(unittest.TestCase):
    def test_domain_rejects_code_paths_and_ips(self):
        for value in ['https://admin.example.com', 'admin.example.com:443', '127.0.0.1', 'a..com', 'a.com;id', 'a.com\nserver {}', 'localhost', 'a.invalid', '-a.com', 'a-.com']:
            with self.subTest(value=value), self.assertRaises(ValueError): i.domain_name(value)
        self.assertEqual(i.domain_name(' ADMIN.Example.COM. '), 'admin.example.com')
        self.assertEqual(i.domain_name('管理.example.com'), 'xn--8ey35n.example.com')

    def test_credentials_are_fresh_and_do_not_use_fixed_defaults(self):
        a, b = i.controller_env('admin.example.com'), i.controller_env('admin.example.com')
        for key in ['DATABASE_URL', 'DNSDOH_ADMIN_USERNAME', 'DNSDOH_ADMIN_PASSWORD', 'DNSDOH_MASTER_KEY']: self.assertNotEqual(a[key], b[key])
        self.assertEqual(len(a['DNSDOH_MASTER_KEY']), 43)
        self.assertGreaterEqual(len(a['DNSDOH_ADMIN_PASSWORD']), 32)
        self.assertNotIn('PASSWORD', a['DNSDOH_ADMIN_PASSWORD'])

    def test_atomic_write_rejects_link_and_protects_secrets(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('DNSDOH_TEST_TMP', '/mnt/youlin-data/tmp')) as d:
            p = Path(d) / 'secret'; i.atomic(p, 'first'); self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            i.atomic(p, 'second'); self.assertEqual(p.read_text(), 'second')
            link = Path(d) / 'link'; link.symlink_to(p)
            with self.assertRaises(RuntimeError): i.atomic(link, 'bad')
            self.assertEqual(p.read_text(), 'second')

    def test_foreign_configuration_never_overwritten(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('DNSDOH_TEST_TMP', '/mnt/youlin-data/tmp')) as d:
            p = Path(d) / 'config'; p.write_text('belongs to another service')
            with self.assertRaises(RuntimeError): i.managed(p, 'new')
            self.assertEqual(p.read_text(), 'belongs to another service')

    def test_nginx_failure_restores_working_configuration(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('DNSDOH_TEST_TMP', '/mnt/youlin-data/tmp')) as d:
            p = Path(d) / 'nginx.conf'; old = i.MARKER + 'working'; p.write_text(old)
            with patch.object(i, 'NGINX', p), patch.object(i, 'run', side_effect=RuntimeError('nginx invalid')):
                with self.assertRaises(RuntimeError): i.apply_nginx('admin.example.com', True)
            self.assertEqual(p.read_text(), old)

    def test_plaintext_doh_never_redirects_credential(self):
        for tls in [False, True]:
            config = i.http_config('admin.example.com', tls)
            self.assertIn('location /dns-query/ { return 400; }', config)
            self.assertIn('access_log off;', config)
            self.assertNotIn('/gateway/', config)
        self.assertIn('ssl_protocols TLSv1.2 TLSv1.3;', i.http_config('admin.example.com', True))

    def bootstrap_extract(self, directory, member, content=b'payload', bad_checksum=False):
        directory = Path(directory)
        bundle = directory / 'bundle.tar.gz'
        with tarfile.open(bundle, 'w:gz') as archive:
            archive.addfile(member, io.BytesIO(content) if member.isfile() else None)
        checksums = directory / 'SHA256SUMS'
        digest = '0' * 64 if bad_checksum else hashlib.sha256(bundle.read_bytes()).hexdigest()
        checksums.write_text(digest + '  bundle.tar.gz\n')
        script = (ROOT / 'install.sh').read_text().split("<<'PY'\n", 1)[1].split('\nPY', 1)[0]
        return subprocess.run([sys.executable, '-c', script, str(bundle), str(checksums), str(directory / 'out')], capture_output=True)

    def test_bootstrap_extracts_verified_regular_files(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('DNSDOH_TEST_TMP', '/mnt/youlin-data/tmp')) as d:
            member = tarfile.TarInfo('DNSDOH/agent/dnsdoh'); member.size = 7; member.mode = 0o755
            self.assertEqual(self.bootstrap_extract(d, member).returncode, 0)
            self.assertEqual((Path(d) / 'out/DNSDOH/agent/dnsdoh').read_bytes(), b'payload')

    def test_bootstrap_rejects_unverified_paths_and_links(self):
        for case in ['checksum', 'traversal', 'symlink', 'hardlink']:
            with self.subTest(case=case), tempfile.TemporaryDirectory(dir=os.environ.get('DNSDOH_TEST_TMP', '/mnt/youlin-data/tmp')) as d:
                member = tarfile.TarInfo('DNSDOH/agent/dnsdoh'); member.size = 7
                if case == 'traversal': member.name = 'DNSDOH/../../escape'
                if case in ['symlink', 'hardlink']:
                    member.type = tarfile.SYMTYPE if case == 'symlink' else tarfile.LNKTYPE
                    member.linkname = '/etc/passwd'; member.size = 0
                self.assertNotEqual(self.bootstrap_extract(d, member, bad_checksum=case == 'checksum').returncode, 0)
                self.assertFalse((Path(d) / 'out').exists())

    def test_supported_main_platforms_are_explicit(self):
        for name, version in [('debian','12'),('debian','13'),('ubuntu','22.04'),('ubuntu','24.04')]: self.assertTrue(i.supported_os({'ID':name,'VERSION_ID':version}))
        for name, version in [('debian','10'),('ubuntu','20.04'),('alpine','3.23')]: self.assertFalse(i.supported_os({'ID':name,'VERSION_ID':version}))

if __name__ == '__main__': unittest.main(verbosity=2)
