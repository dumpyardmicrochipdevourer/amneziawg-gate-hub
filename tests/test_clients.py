from pathlib import Path
import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'roles/amneziawg-cascade/files/cascade_clients.py'
spec = importlib.util.spec_from_file_location('cascade_clients', SOURCE)
clients = importlib.util.module_from_spec(spec)
spec.loader.exec_module(clients)

class ClientsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.config = self.base/'awg0.conf'
        self.config.write_text('[Interface]\nPrivateKey = server-private\nAddress = 10.2.0.1/24\nListenPort = 51820\nMTU = 1280\nJc = 4\nS1 = 30\n\n[Peer]\n# phone\nPublicKey = '+ 'P'*43+'=\nAllowedIPs = 10.2.0.2/32\n')
        (self.base/'cascade-settings.json').write_text(json.dumps({'interface':'awg0','endpoint':'203.0.113.10','dns':'1.1.1.1'}))
        self.calls=[]
        def awg(*args, input=None):
            self.calls.append(args)
            if args[0]=='show': return 'S'*43+'='
            if args[0]=='genkey': return 'private-test-key'
            if args[0]=='pubkey': return 'N'*43+'='
            return ''
        self.mock = patch.object(clients, 'awg', side_effect=awg)
        self.mock.start(); self.addCleanup(self.mock.stop)
    def call(self, action, name=None):
        out=io.StringIO()
        with contextlib.redirect_stdout(out): clients.manage(self.base, action, name)
        return out.getvalue()
    def test_add_and_list_do_not_expose_private_keys(self):
        result=self.call('add','tablet')
        profile=self.base/'cascade-clients/tablet.conf'
        self.assertIn(str(profile), result)
        self.assertIn('Endpoint = 203.0.113.10:51820',profile.read_text())
        self.assertIn('Address = 10.2.0.3/32',profile.read_text())
        self.assertIn('S1 = 30', profile.read_text())
        self.assertEqual(profile.stat().st_mode & 0o777,0o600)
        self.assertIn('tablet',self.call('list'))
        self.assertNotIn('private-test-key',self.call('list')+result)
        registry=json.loads((self.base/'cascade-clients.json').read_text())
        self.assertEqual(registry['clients'][0]['name'],'tablet')
        self.assertNotIn('private',json.dumps(registry))
    def test_remove_inventory_client_persists_revocation(self):
        self.call('remove','phone')
        self.assertNotIn('# phone',self.config.read_text())
        self.assertIn('phone',json.loads((self.base/'cascade-clients.json').read_text())['removed'])
        self.assertIn(('set','awg0','peer','P'*43+'=','remove'),self.calls)
    def test_remove_dynamic_client_and_reuse_address(self):
        self.call('add','tablet'); self.call('remove','tablet')
        self.assertFalse((self.base/'cascade-clients/tablet.conf').exists())
        self.assertFalse((self.base/'cascade-keys/client-tablet.key').exists())
        self.call('add','replacement')
        self.assertIn('10.2.0.3/32',(self.base/'cascade-clients/replacement.conf').read_text())
    def test_failed_runtime_apply_restores_files(self):
        original=self.config.read_bytes()
        def fail(*args,input=None):
            if args[0]=='set': raise RuntimeError('apply failed')
            return 'N'*43+'='
        with patch.object(clients,'awg',side_effect=fail):
            with self.assertRaises(RuntimeError): self.call('add','tablet')
            with self.assertRaises(RuntimeError): self.call('remove','phone')
        self.assertEqual(original,self.config.read_bytes())
        self.assertFalse((self.base/'cascade-clients/tablet.conf').exists())
        self.assertFalse((self.base/'cascade-clients.json').exists())
    def test_interrupted_remove_is_recovered_on_next_command(self):
        original=self.config.read_bytes()
        saved_awg=clients.awg
        def interrupt(*args,input=None):
            if args[0]=='set': raise KeyboardInterrupt()
            return saved_awg(*args,input=input)
        with patch.object(clients,'awg',side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt): self.call('remove','phone')
        self.call('list')
        self.assertEqual(self.config.read_bytes(), original)
        self.assertFalse((self.base/'cascade-clients.json').exists())
    def test_deploy_marker_and_bad_names_block_mutation(self):
        original=self.config.read_bytes()
        for name in ['../bad','phone','a name']:
            with self.assertRaises(ValueError): self.call('add',name)
        (self.base/'.cascade-deploy').mkdir()
        with self.assertRaises(ValueError): self.call('add','tablet')
        self.assertEqual(original,self.config.read_bytes())

if __name__ == '__main__': unittest.main()
