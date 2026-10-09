#!/usr/bin/env python3
import hashlib,io,json,pathlib,tarfile,gzip,shutil
root=pathlib.Path(__file__).resolve().parent.parent
dist=root/'dist'
files=['luci-app-routerbox-0.2.0-r6.apk','routerbox-core-1.14.2-r13.apk','keys/routerbox.pub','manifest.json','install.sh','README.ru.md','INSTALL.ru.md']
shutil.copyfile(root/'install.sh',dist/'install.sh')
(dist/'README.ru.md').write_text((root/'README.md').read_text().replace('](docs/INSTALL.md', '](https://github.com/nekl3103/RouterBox/blob/main/docs/INSTALL.md'))
(dist/'INSTALL.ru.md').write_text((root/'docs/INSTALL.md').read_text().replace('](../README.md)', '](README.ru.md)'))
checks=''.join(hashlib.sha256((dist/name).read_bytes()).hexdigest()+'  '+name+'\n' for name in files)
(dist/'SHA256SUMS').write_text(checks)
files.append('SHA256SUMS')
with (dist/'routerbox-mt7621-0.2.0.tar.gz').open('wb') as f:
 with gzip.GzipFile(fileobj=f,mode='wb',mtime=0,filename='') as gz:
  with tarfile.open(fileobj=gz,mode='w|') as tar:
   for name in sorted(files):
    data=(dist/name).read_bytes();info=tarfile.TarInfo('routerbox-mt7621/'+name);info.size=len(data);info.mode=0o755 if name=='install.sh' else 0o644;info.mtime=0;tar.addfile(info,io.BytesIO(data))
print(json.dumps({'bundle_bytes':(dist/'routerbox-mt7621-0.2.0.tar.gz').stat().st_size,'app_apk_bytes':(dist/files[0]).stat().st_size,'core_apk_bytes':(dist/files[1]).stat().st_size}))
