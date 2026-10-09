#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p build dist/keys
if [ ! -f build/routerbox-private.pem ]; then
 openssl genrsa -out build/routerbox-private.pem 2048
 chmod 600 build/routerbox-private.pem
fi
openssl rsa -in build/routerbox-private.pem -pubout -out dist/keys/routerbox.pub
# Pin the builder image, including apk-tools 3.0.7. No SDK or toolchain on the router.
docker run --rm -v "$PWD:/work" -w /work alpine@sha256:020dfcbaaf4cc1078bf2d9c7ba31a8466e334061dcd2f248001d68f79e52c000 sh -eu -c '
 apk mkpkg --compat 3.0.0 --compression deflate:9 --sign-key build/routerbox-private.pem --files build/stage-app --info name:luci-app-routerbox --info version:0.3.0-r1 --info arch:mipsel_24kc --info license:GPL-3.0-or-later --info description:"RouterBox LuCI subscriptions, DNS and routing" --info depends:"luci-base rpcd jsonfilter ca-bundle kmod-tun kmod-nft-nat kmod-nft-queue ip-full nftables-json" --script post-install:scripts/post-install --script pre-deinstall:scripts/pre-deinstall --output dist/luci-app-routerbox-0.3.0-r1.apk
 apk mkpkg --compat 3.0.0 --compression deflate:9 --sign-key build/routerbox-private.pem --files build/stage-core --info name:routerbox-core --info version:1.14.2-r13 --info arch:mipsel_24kc --info license:GPL-3.0-or-later --info description:"Compressed sing-box-lx client core for MT7621" --output dist/routerbox-core-1.14.2-r13.apk
 apk --keys-dir /work/dist/keys verify dist/luci-app-routerbox-0.3.0-r1.apk dist/routerbox-core-1.14.2-r13.apk
 apk adbdump dist/luci-app-routerbox-0.3.0-r1.apk > build/app-package-metadata.txt
 apk adbdump dist/routerbox-core-1.14.2-r13.apk > build/core-package-metadata.txt
'
python3 scripts/bundle.py
