#!/usr/bin/env python3
"""Safety checks for an installer that writes system configuration; no host mutations."""
import importlib.util
import os
import hashlib
import io
import json
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
        with tempfile.TemporaryDirectory(dir=os.environ.get('DNSDOH_TEST_TMP', tempfile.gettempdir())) as d:
            p = Path(d) / 'secret'; i.atomic(p, 'first'); self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            i.atomic(p, 'second'); self.assertEqual(p.read_text(), 'second')
            link = Path(d) / 'link'; link.symlink_to(p)
            with self.assertRaises(RuntimeError): i.atomic(link, 'bad')
            self.assertEqual(p.read_text(), 'second')

    def test_foreign_configuration_never_overwritten(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('DNSDOH_TEST_TMP', tempfile.gettempdir())) as d:
            p = Path(d) / 'config'; p.write_text('belongs to another service')
            with self.assertRaises(RuntimeError): i.managed(p, 'new')
            self.assertEqual(p.read_text(), 'belongs to another service')

    def test_nginx_failure_restores_working_configuration(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('DNSDOH_TEST_TMP', tempfile.gettempdir())) as d:
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
        with tempfile.TemporaryDirectory(dir=os.environ.get('DNSDOH_TEST_TMP', tempfile.gettempdir())) as d:
            member = tarfile.TarInfo('DNSDOH/agent/dnsdoh'); member.size = 7; member.mode = 0o755
            self.assertEqual(self.bootstrap_extract(d, member).returncode, 0)
            self.assertEqual((Path(d) / 'out/DNSDOH/agent/dnsdoh').read_bytes(), b'payload')

    def test_bootstrap_rejects_unverified_paths_and_links(self):
        for case in ['checksum', 'traversal', 'symlink', 'hardlink']:
            with self.subTest(case=case), tempfile.TemporaryDirectory(dir=os.environ.get('DNSDOH_TEST_TMP', tempfile.gettempdir())) as d:
                member = tarfile.TarInfo('DNSDOH/agent/dnsdoh'); member.size = 7
                if case == 'traversal': member.name = 'DNSDOH/../../escape'
                if case in ['symlink', 'hardlink']:
                    member.type = tarfile.SYMTYPE if case == 'symlink' else tarfile.LNKTYPE
                    member.linkname = '/etc/passwd'; member.size = 0
                self.assertNotEqual(self.bootstrap_extract(d, member, bad_checksum=case == 'checksum').returncode, 0)
                self.assertFalse((Path(d) / 'out').exists())

    def test_default_and_custom_paths_reach_all_generated_services(self):
        previous = str(i.DATA)
        try:
            for directory in ['/opt/dnsdoh', '/srv/dnsdoh-test']:
                i.configure_paths(directory)
                units = {}
                with patch.object(i, 'unit', side_effect=lambda name, body: units.__setitem__(name, body)), patch.object(i, 'atomic'), patch.object(i, 'run'):
                    i.install_units(ROOT)
                joined = '\n'.join(units.values())
                self.assertIn('EnvironmentFile=' + directory + '/runtime/%i.env', joined)
                self.assertIn('controller-maintain --root ' + directory + '/runtime/direct-tls', joined)
                self.assertIn('--env ' + directory + '/runtime/controller.env --output ' + directory + '/runtime/backups', joined)
                self.assertIn('--config-dir ' + directory + '/runtime/letsencrypt', joined)
                self.assertIn('alias ' + directory + '/hosting/downloads/', i.http_config('admin.example.com', True))
                if directory != '/opt/dnsdoh': self.assertNotIn('/opt/dnsdoh', joined)
        finally:
            i.configure_paths(previous)

    def test_install_directory_rejects_unsafe_configuration_values(self):
        for directory in ['/', '/opt', 'relative', '/srv/a b', '/srv/a%u', '/srv/a;id', '/srv/../etc', '/srv/a\nExecStart=bad', '/root/dnsdoh', '/home/user/dnsdoh', '/tmp/dnsdoh', '/var/tmp/dnsdoh']:
            with self.subTest(directory=directory), self.assertRaises(ValueError): i.configure_paths(directory)
        with tempfile.TemporaryDirectory() as d:
            link = Path(d) / 'linked'; link.symlink_to(Path(d))
            with self.assertRaises(ValueError): i.configure_paths(str(link / 'child'))

    @unittest.skipUnless(os.geteuid() == 0, "bootstrap requires root; run via sudo in CI")
    def test_bootstrap_passes_selected_directory_before_any_install(self):
        # Exercise the actual bootstrap, download validation and unpacking with a
        # local release fixture. The fake installer only reports its argv.
        with tempfile.TemporaryDirectory() as d:
            base = Path(d); fixture = base / 'fixture'; fixture.mkdir()
            payload = b'import sys,json; print(json.dumps(sys.argv[1:]))\n'
            bundle = fixture / 'DNSDOH-linux-amd64.tar.gz'
            with tarfile.open(bundle, 'w:gz') as archive:
                member = tarfile.TarInfo('DNSDOH/scripts/install-controller.py'); member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
            (fixture / 'SHA256SUMS').write_text(hashlib.sha256(bundle.read_bytes()).hexdigest() + '  ' + bundle.name + '\n')
            fakebin = base / 'bin'; fakebin.mkdir()
            curl = fakebin / 'curl'
            curl.write_text('#!/usr/bin/env python3\nimport os,sys,shutil\na=sys.argv[1:]; url=next(x for x in a if x.startswith("https://")); shutil.copyfile(os.environ["FIXTURE"]+"/"+url.rsplit("/",1)[1],a[a.index("-o")+1])\n'); curl.chmod(0o755)
            for mode in ['environment', 'argument']:
                selected = base / mode
                env = {**os.environ, 'PATH': str(fakebin) + ':' + os.environ['PATH'], 'FIXTURE': str(fixture), 'DNSDOH_DATA_ROOT': str(selected if mode == 'environment' else base / 'unused')}
                args = [] if mode == 'environment' else ['--data-dir', str(selected)]
                result = subprocess.run(['bash', str(ROOT / 'install.sh'), *args, '--domain', 'admin.example.com'], env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                argv = json.loads(result.stdout.splitlines()[-1])
                self.assertEqual(argv, ['--data-dir', str(selected), '--domain', 'admin.example.com'])
                self.assertTrue((selected / 'installer/cache' / bundle.name).exists())
                self.assertFalse((base / 'unused').exists())

    def test_supported_main_platforms_are_explicit(self):
        for name, version in [('debian','12'),('debian','13'),('ubuntu','22.04'),('ubuntu','24.04')]: self.assertTrue(i.supported_os({'ID':name,'VERSION_ID':version}))
        for name, version in [('debian','10'),('ubuntu','20.04'),('alpine','3.23')]: self.assertFalse(i.supported_os({'ID':name,'VERSION_ID':version}))

if __name__ == '__main__': unittest.main(verbosity=2)
