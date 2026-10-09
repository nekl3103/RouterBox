#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export GOTOOLCHAIN=go1.26.8
export GOMODCACHE="$PWD/build/gomod"
export GOCACHE="$PWD/build/gocache"
export CGO_ENABLED=0
mkdir -p build
ARCH=$(go env GOARCH)
case "$ARCH" in amd64|arm64) ;; *) echo "Unsupported test host: $ARCH" >&2; exit 1;; esac
./scripts/patch-core.sh
GOOS=linux GOARCH="$ARCH" go test -c -o "build/routerbox-tests-linux-$ARCH" ./internal/routerbox
(
 cd build/core-source
 GOOS=linux GOARCH="$ARCH" go build -trimpath -tags with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api,with_xhttp,with_awg -ldflags '-s -w -buildid= -checklinkname=0 -X github.com/sagernet/sing-box/constant.Version=1.14.2-lx.12-router.1' -o "../sing-box-linux-$ARCH" ./cmd/sing-box
)
docker run --rm -v "$PWD:/work:ro" -e "ROUTERBOX_TEST_CORE=/work/build/sing-box-linux-$ARCH" -e ROUTERBOX_TEST_SERVICES alpine@sha256:020dfcbaaf4cc1078bf2d9c7ba31a8466e334061dcd2f248001d68f79e52c000 /work/"build/routerbox-tests-linux-$ARCH" -test.v
