// Copyright 2026 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tarfs_test

import (
	"archive/tar"
	"crypto/sha1" //nolint:gosec // APK per-file checksums are SHA-1
	"encoding/hex"
	"io/fs"
	"os"
	"testing"
	"testing/fstest"

	"chainguard.dev/apko/internal/contentdigest"
	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/tarfs"
)

// digestingFS names each entry's content by digest, as an
// apk.ContentDigester.
type digestingFS struct {
	fstest.MapFS
	digests map[string]string
}

func (d digestingFS) ContentDigest(name string) (string, bool) {
	dg, ok := d.digests[name]
	return dg, ok
}

func TestContentDigest(t *testing.T) {
	const content = "package content"
	sum := sha1.Sum([]byte(content)) //nolint:gosec
	reg := func(name string) tar.Header {
		return tar.Header{
			Typeflag:   tar.TypeReg,
			Name:       name,
			Mode:       0o644,
			Size:       int64(len(content)),
			PAXRecords: map[string]string{"APK-TOOLS.checksum.SHA1": hex.EncodeToString(sum[:])},
		}
	}
	names := []string{"kept", "chmodded", "chowned", "rewritten", "appended", "opened-rw", "removed", "nodigest", "plain-source"}
	src := digestingFS{MapFS: fstest.MapFS{}, digests: map[string]string{}}
	plain := fstest.MapFS{}
	for _, n := range names {
		src.MapFS[n] = &fstest.MapFile{Data: []byte(content)}
		plain[n] = &fstest.MapFile{Data: []byte(content)}
		if n != "nodigest" {
			src.digests[n] = "test:" + n
		}
	}
	pkg := &apk.Package{Name: "p", Origin: "p"}

	m := tarfs.New()
	for _, n := range names {
		var from fs.FS = src
		if n == "plain-source" {
			from = plain
		}
		if _, err := m.WriteHeader(reg(n), from, pkg); err != nil {
			t.Fatal(err)
		}
	}
	m.WriteFile("created", []byte(content), 0o644) //nolint:errcheck

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(m.Chmod("chmodded", 0o600))
	must(m.Chown("chowned", 1000, 1000))
	must(m.WriteFile("rewritten", []byte("other"), 0o644))
	f, err := m.OpenFile("appended", os.O_WRONLY|os.O_APPEND, 0o644)
	must(err)
	_, err = f.Write([]byte("more"))
	must(err)
	must(f.Close())
	// Opened to be modified, but nothing written: its content is now held in
	// memory, so it is hashed rather than taken from the package.
	f, err = m.OpenFile("opened-rw", os.O_RDWR, 0o644)
	must(err)
	must(f.Close())
	must(m.Remove("removed"))
	must(m.WriteFile("removed", []byte(content), 0o644))
	must(m.MkdirAll("dir", 0o755))

	// A file still as installed is named by the package contents' digest when
	// they give one; anything else is named by the SHA-256 of what it serves.
	for name, want := range map[string]string{
		"kept":         "test:kept",
		"chmodded":     "test:chmodded",
		"chowned":      "test:chowned",
		"rewritten":    contentdigest.OfBytes([]byte("other")),
		"appended":     contentdigest.OfBytes([]byte(content + "more")),
		"opened-rw":    contentdigest.OfBytes([]byte(content)),
		"removed":      contentdigest.OfBytes([]byte(content)),
		"nodigest":     contentdigest.OfBytes([]byte(content)),
		"plain-source": contentdigest.OfBytes([]byte(content)),
		"created":      contentdigest.OfBytes([]byte(content)),
		"dir":          "",
	} {
		info, err := m.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		got, err := info.(interface{ ContentDigest() (string, error) }).ContentDigest()
		if err != nil || got != want {
			t.Errorf("%s: ContentDigest() = %q, %v; want %q", name, got, err, want)
		}
	}
}
