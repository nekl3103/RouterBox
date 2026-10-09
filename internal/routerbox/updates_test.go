package routerbox

import (
	"encoding/json"
	"testing"
)

func TestReleaseVersionsAndMT7621(t *testing.T) {
	for _, c := range []struct {
		latest, current string
		want            bool
	}{{"v0.3.10", "0.3.9", true}, {"v0.3.3", "0.3.3", false}, {"v0.2.9", "0.3.3", false}, {"v1.0.0", "0.99.99", true}} {
		got, e := newerVersion(c.latest, c.current)
		if e != nil || got != c.want {
			t.Fatal(c, got, e)
		}
	}
	release := Object{"tag_name": "v0.3.10", "assets": []Object{{"name": "routerbox-mt7621-0.3.10.tar.gz", "browser_download_url": "https://evil.example/"}}}
	b, _ := json.Marshal(release)
	info, e := releaseInfo(b, "0.3.3")
	if e != nil || info["available"] != true || info["download"] != "https://github.com/nekl3103/RouterBox/releases/download/v0.3.10/routerbox-mt7621-0.3.10.tar.gz" {
		t.Fatal(info, e)
	}
	for _, tag := range []string{"v0.3.4-rc1", "../../evil", "v0.3.4?token=bad"} {
		release["tag_name"] = tag
		b, _ = json.Marshal(release)
		if _, e = releaseInfo(b, "0.3.3"); e == nil {
			t.Fatal("unsafe tag accepted")
		}
	}
	release["tag_name"] = "v0.3.10"
	release["prerelease"] = true
	b, _ = json.Marshal(release)
	if _, e = releaseInfo(b, "0.3.3"); e == nil {
		t.Fatal("prerelease accepted")
	}
	delete(release, "prerelease")
	delete(release, "assets")
	b, _ = json.Marshal(release)
	if _, e = releaseInfo(b, "0.3.3"); e == nil {
		t.Fatal("missing MT7621 package accepted")
	}
}
