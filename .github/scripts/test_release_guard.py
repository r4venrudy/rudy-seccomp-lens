import importlib.util,io,tempfile,unittest,zipfile,tarfile
from pathlib import Path
spec=importlib.util.spec_from_file_location('guard',Path(__file__).with_name('release_guard.py'));guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)
class ReleaseIntegrityTests(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def zip(self,name='one.zip',content=b'invented payload'):
        path=self.root/name
        with zipfile.ZipFile(path,'w') as z:z.writestr('bin/tool',content)
        return path
    def test_zip_integrity(self):self.assertEqual(guard.verify(self.zip()),(1,16))
    def test_payload_crc_failure(self):
        path=self.zip();data=path.read_bytes().replace(b'invented payload',b'changed! payload');path.write_bytes(data)
        with self.assertRaises((zipfile.BadZipFile,ValueError)):guard.verify(path)
    def test_truncated_zip(self):
        path=self.zip();path.write_bytes(path.read_bytes()[:-8])
        with self.assertRaises((zipfile.BadZipFile,ValueError)):guard.verify(path)
    def test_member_budget(self):
        path=self.zip();previous=guard.MAX_MEMBER
        try:
            guard.MAX_MEMBER=1
            with self.assertRaises(ValueError):guard.verify(path)
        finally:guard.MAX_MEMBER=previous
    def test_count_budget(self):
        path=self.zip();previous=guard.MAX_ENTRIES
        try:
            guard.MAX_ENTRIES=0
            with self.assertRaises(ValueError):guard.verify(path)
        finally:guard.MAX_ENTRIES=previous
    def test_tar_payload(self):
        path=self.root/'one.tar.gz'
        with tarfile.open(path,'w:gz') as t:
            m=tarfile.TarInfo('bin/tool');m.size=3;t.addfile(m,io.BytesIO(b'abc'))
        self.assertEqual(guard.verify(path),(1,3))
    def test_symlink_input(self):
        if __import__('os').name=='nt':self.skipTest('symlink creation needs optional Windows privileges')
        path=self.zip();link=self.root/'linked.zip';link.symlink_to(path)
        with self.assertRaises(ValueError):guard.verify(link)
class ReleasePathTests(unittest.TestCase):
    def test_reject_zip_paths(self):
        for member in ['../escape','/absolute','C:/drive','folder\\escape','a/../b','stream:name','AUX.txt','trailing.']:
            with self.subTest(member=member):
                path=self.root/'unsafe.zip'
                normalized=member.replace('\\','/')
                with zipfile.ZipFile(path,'w') as z:z.writestr(normalized,b'invented')
                if normalized!=member:path.write_bytes(path.read_bytes().replace(normalized.encode(),member.encode()))
                with self.assertRaises(ValueError):guard.verify(path)
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def test_collision(self):
        path=self.root/'collision.zip'
        for names in [('One.txt','one.txt'),('folder/file','folder//file'),('file','file/child'),('caf\u00e9','cafe\u0301')]:
            with zipfile.ZipFile(path,'w') as z:
                for name in names:z.writestr(name,b'example')
            with self.assertRaises(ValueError):guard.verify(path)
    def test_zip_link(self):
        path=self.root/'link.zip';info=zipfile.ZipInfo('linked');info.create_system=3;info.external_attr=0o120777<<16
        with zipfile.ZipFile(path,'w') as z:z.writestr(info,b'target')
        with self.assertRaises(ValueError):guard.verify(path)
    def test_tar_link(self):
        path=self.root/'link.tar.gz'
        with tarfile.open(path,'w:gz') as t:
            m=tarfile.TarInfo('linked');m.type=tarfile.SYMTYPE;m.linkname='../escape';t.addfile(m)
        with self.assertRaises(ValueError):guard.verify(path)
    def test_portable_directories(self):
        path=self.root/'portable.tar.gz'
        with tarfile.open(path,'w:gz') as t:
            m=tarfile.TarInfo('./');m.type=tarfile.DIRTYPE;t.addfile(m)
            m=tarfile.TarInfo('./bin/');m.type=tarfile.DIRTYPE;t.addfile(m)
            m=tarfile.TarInfo('./bin/tool');m.size=3;t.addfile(m,io.BytesIO(b'abc'))
        self.assertEqual(guard.verify(path),(3,3))

if __name__=='__main__':unittest.main()
