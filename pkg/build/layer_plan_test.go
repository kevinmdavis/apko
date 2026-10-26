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

package build

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1" //nolint:gosec // APK per-file checksums are SHA-1
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/go-cmp/cmp"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"chainguard.dev/apko/internal/contentdigest"
	"chainguard.dev/apko/pkg/apk/apk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/tarfs"
)

// planFixture is a built filesystem the way an apko build leaves it: package
// files installed through tarfs's WriteHeader, from each package's contents,
// and files the build wrote itself on top.
type planFixture struct {
	fsys      apkfs.FullFS
	groups    []*group
	pkgToDiff map[*apk.Package][]byte
}

// digestingFS is package contents that name each regular entry's content by
// digest without reading it (see apk.ContentDigester), with report.
type digestingFS struct {
	fstest.MapFS
	report func(name string, data []byte) string
}

func (d digestingFS) ContentDigest(name string) (string, bool) {
	f, ok := d.MapFS[name]
	if !ok {
		return "", false
	}
	return d.report(name, f.Data), true
}

// sha256Of is the digest planning gives content it hashes itself.
func sha256Of(b []byte) string { return contentdigest.OfBytes(b) }

func newPlanFixture(t *testing.T) planFixture {
	return newPlanFixtureReporting(t, func(_ string, data []byte) string { return sha256Of(data) })
}

// newPlanFixtureReporting is newPlanFixture with package contents that report
// digests with report.
func newPlanFixtureReporting(t *testing.T, report func(name string, data []byte) string) planFixture {
	t.Helper()
	fsys := tarfs.New()

	pkgA := &apk.Package{Name: "a", Origin: "a", Version: "1", InstalledSize: 3000}
	pkgB := &apk.Package{Name: "b", Origin: "b", Version: "1", InstalledSize: 2000}
	pkgBDev := &apk.Package{Name: "b-dev", Origin: "b", Version: "1", InstalledSize: 100}

	at := func(sec int64) time.Time { return time.Unix(sec, 0).UTC() }
	reg := func(name string, content string, mtime int64, pax map[string]string) (tar.Header, []byte) {
		sum := sha1.Sum([]byte(content)) //nolint:gosec
		records := map[string]string{"APK-TOOLS.checksum.SHA1": hex.EncodeToString(sum[:])}
		maps.Copy(records, pax)
		return tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: int64(len(content)), ModTime: at(mtime), PAXRecords: records}, []byte(content)
	}
	dir := func(name string, mtime int64) tar.Header {
		return tar.Header{Typeflag: tar.TypeDir, Name: name, Mode: 0o755, ModTime: at(mtime)}
	}

	install := func(pkg *apk.Package, hdrs ...any) {
		t.Helper()
		src := fstest.MapFS{}
		var entries []tar.Header
		for i := 0; i < len(hdrs); i++ {
			hdr := hdrs[i].(tar.Header)
			if hdr.Typeflag == tar.TypeReg {
				i++
				src[hdr.Name] = &fstest.MapFile{Data: hdrs[i].([]byte), Mode: 0o644}
			}
			entries = append(entries, hdr)
		}
		contents := digestingFS{MapFS: src, report: report}
		for _, hdr := range entries {
			if _, err := fsys.WriteHeader(hdr, contents, pkg); err != nil {
				t.Fatalf("installing %s from %s: %v", hdr.Name, pkg.Name, err)
			}
		}
	}

	aBin, aBinData := reg("usr/bin/a", "a binary\n", 100, map[string]string{"SCHILY.xattr.security.capability": "\x01\x00\x00\x02"})
	aLib, aLibData := reg("usr/lib/liba.so.1", "a library", 110, nil)
	aConf, aConfData := reg("etc/a.conf", "a=1\n", 120, nil)
	aEmpty, aEmptyData := reg("usr/share/a/empty", "", 130, nil)
	install(pkgA,
		dir("etc", 10), dir("usr", 11), dir("usr/bin", 12), dir("usr/lib", 13), dir("usr/share", 14), dir("usr/share/a", 15),
		aBin, aBinData, aLib, aLibData, aConf, aConfData, aEmpty, aEmptyData,
		tar.Header{Typeflag: tar.TypeSymlink, Name: "usr/lib/liba.so", Linkname: "liba.so.1", ModTime: at(111), PAXRecords: map[string]string{"APK-TOOLS.checksum.SHA1": hex.EncodeToString(make([]byte, 20))}},
		tar.Header{Typeflag: tar.TypeLink, Name: "usr/bin/a-alias", Linkname: "usr/bin/a", ModTime: at(100)},
	)

	bBin, bBinData := reg("usr/bin/b", "b binary, a bit longer than a's\n", 200, nil)
	bShare, bShareData := reg("usr/share/b/data", "b data", 210, nil)
	install(pkgB, dir("usr", 21), dir("usr/bin", 22), dir("usr/share", 23), dir("usr/share/b", 24), bBin, bBinData, bShare, bShareData)

	bInc, bIncData := reg("usr/include/b.h", "#define B 1\n", 300, nil)
	install(pkgBDev, dir("usr", 31), dir("usr/include", 32), bInc, bIncData)

	// What the build writes itself: accounts that name owners, a package
	// file it rewrites, ownership, a device, and the installed db.
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(fsys.WriteFile("etc/passwd", []byte("root:x:0:0:root:/root:/bin/sh\nnonroot:x:65532:65532::/home/nonroot:/bin/sh\n"), 0o644))
	must(fsys.WriteFile("etc/group", []byte("root:x:0:\nnonroot:x:65532:\n"), 0o644))
	must(fsys.WriteFile("etc/a.conf", []byte("a=2, rewritten by the build\n"), 0o644))
	must(fsys.Chown("usr/share/b/data", 65532, 65532))
	must(fsys.MkdirAll("dev", 0o755))
	must(fsys.Mknod("dev/null", uint32(0o666|0o020000), int(1<<8|3)))
	must(fsys.MkdirAll("usr/lib/apk/db", 0o755))
	must(fsys.WriteFile(installedDB, []byte("P:a\n\nP:b\n\nP:b-dev\n\n"), 0o644))
	must(fsys.MkdirAll("tmp", 0o1777))

	return planFixture{
		fsys: fsys,
		groups: []*group{
			{pkgs: []*apk.Package{pkgA}, size: 3000, tiebreaker: "a"},
			{pkgs: []*apk.Package{pkgB, pkgBDev}, size: 2100, tiebreaker: "b"},
		},
		pkgToDiff: map[*apk.Package][]byte{
			pkgA:    []byte("P:a\n\n"),
			pkgB:    []byte("P:b\n\n"),
			pkgBDev: []byte("P:b-dev\n\n"),
		},
	}
}

func layerBytes(t *testing.T, l v1.Layer) (compressed, uncompressed []byte) {
	t.Helper()
	read := func(open func() (io.ReadCloser, error)) []byte {
		rc, err := open()
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		b, err := io.ReadAll(rc)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	return read(l.Compressed), read(l.Uncompressed)
}

// TestRenderMatchesBuildLayers holds Render to the layers BuildLayers' own
// streaming writer writes for the same filesystem, byte for byte, whether
// BuildLayers keeps them gzipped or as plain tar until the image needs them,
// for as long as BuildLayers has a writer of its own.
func TestRenderMatchesBuildLayers(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		t.Run(fmt.Sprintf("compressed=%v", compressed), func(t *testing.T) {
			fx := newPlanFixture(t)
			ctx := t.Context()

			want, err := splitLayers(ctx, fx.fsys, fx.groups, fx.pkgToDiff, t.TempDir(), compressed)
			if err != nil {
				t.Fatal(err)
			}
			plans, src, err := planLayers(ctx, fx.fsys, fx.groups, fx.pkgToDiff)
			if err != nil {
				t.Fatal(err)
			}
			if len(plans) != len(want) {
				t.Fatalf("planned %d layers, BuildLayers wrote %d", len(plans), len(want))
			}

			for i := range want {
				wantC, _ := layerBytes(t, want[i])

				var buf bytes.Buffer
				d, err := Render(ctx, plans[i], src, &buf)
				if err != nil {
					t.Fatal(err)
				}
				wantDiffID, err := want[i].DiffID()
				if err != nil {
					t.Fatal(err)
				}
				if d.DiffID != wantDiffID {
					t.Errorf("layer %d: Render diffid = %s, want %s", i, d.DiffID, wantDiffID)
				}
				wantDigest, err := want[i].Digest()
				if err != nil {
					t.Fatal(err)
				}
				if d.Digest != wantDigest || d.Size != int64(len(wantC)) || !bytes.Equal(buf.Bytes(), wantC) {
					t.Errorf("layer %d: Render digest = %s (%d bytes), want %s (%d bytes)", i, d.Digest, d.Size, wantDigest, len(wantC))
				}
			}
		})
	}
}

// gunzip is the tar a gzipped layer holds.
func gunzip(t *testing.T, b []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type writtenEntry struct {
	Header  tar.Header
	Content string
}

// readTar reads every entry of the tar in b.
func readTar(t *testing.T, b []byte) []writtenEntry {
	t.Helper()
	var out []writtenEntry
	tr := tar.NewReader(bytes.NewReader(b))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		c, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, writtenEntry{Header: *hdr, Content: string(c)})
	}
}

// TestLayerPlanEntries holds Entries to what Render writes: every header, in
// order, and for every regular file with content, the digest of the content.
func TestLayerPlanEntries(t *testing.T) {
	fx := newPlanFixture(t)
	ctx := t.Context()
	plans, src, err := planLayers(ctx, fx.fsys, fx.groups, fx.pkgToDiff)
	if err != nil {
		t.Fatal(err)
	}

	for i, p := range plans {
		var buf bytes.Buffer
		if _, err := Render(ctx, p, src, &buf); err != nil {
			t.Fatal(err)
		}
		written := readTar(t, gunzip(t, buf.Bytes()))

		// Round trip the planned headers through archive/tar, as the written
		// entries did.
		var tw bytes.Buffer
		w := tar.NewWriter(&tw)
		var digests []string
		for _, e := range p.Entries() {
			if err := w.WriteHeader(&e.Header); err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(make([]byte, e.Header.Size)); err != nil {
				t.Fatal(err)
			}
			digests = append(digests, e.Digest)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		planned := readTar(t, tw.Bytes())
		if len(planned) != len(written) {
			t.Fatalf("layer %d: %d entries planned, %d written", i, len(planned), len(written))
		}
		for j := range written {
			if diff := cmp.Diff(written[j].Header, planned[j].Header); diff != "" {
				t.Errorf("layer %d: %s: header differs from what Render writes (-written +planned):\n%s", i, written[j].Header.Name, diff)
			}
			want := ""
			if hasContent(&written[j].Header) {
				want = sha256Of([]byte(written[j].Content))
			}
			if digests[j] != want {
				t.Errorf("layer %d: %s: digest %q, want %q", i, written[j].Header.Name, digests[j], want)
			}
		}
	}
}

// TestLayerPlanReportedDigests checks that a digest the build filesystem
// reports is planned as it is, in whatever algorithm, without the content
// being read, and that Render still writes the content; and that content no
// digest was reported for is named by its SHA-256.
func TestLayerPlanReportedDigests(t *testing.T) {
	ctx := t.Context()
	fx := newPlanFixtureReporting(t, func(name string, _ []byte) string { return "test:" + name })
	plans, src, err := planLayers(ctx, fx.fsys, fx.groups, fx.pkgToDiff)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for i, p := range plans {
		for _, e := range p.Entries() {
			got[fmt.Sprintf("%d:%s", i, e.Header.Name)] = e.Digest
		}
	}
	for key, want := range map[string]string{
		"0:usr/bin/a":         "test:usr/bin/a",
		"1:usr/bin/b":         "test:usr/bin/b",
		"1:usr/share/b/data":  "test:usr/share/b/data", // chown keeps the content
		"0:etc/a.conf":        sha256Of([]byte("a=2, rewritten by the build\n")),
		"2:etc/passwd":        sha256Of([]byte("root:x:0:0:root:/root:/bin/sh\nnonroot:x:65532:65532::/home/nonroot:/bin/sh\n")),
		"0:" + installedDB:    sha256Of([]byte("P:a\n\n")),
		"0:usr/bin/a-alias":   "", // a hard link
		"0:usr/share/a/empty": "",
	} {
		if got[key] != want {
			t.Errorf("%s: digest %q, want %q", key, got[key], want)
		}
	}

	var buf bytes.Buffer
	if _, err := Render(ctx, plans[1], src, &buf); err != nil {
		t.Fatal(err)
	}
	for _, e := range readTar(t, gunzip(t, buf.Bytes())) {
		if e.Header.Name == "usr/bin/b" && e.Content != "b binary, a bit longer than a's\n" {
			t.Errorf("usr/bin/b rendered as %q", e.Content)
		}
	}
}

// TestLayerPlanDigest checks that a plan's Digest names its layer: the same
// for the same build, and different when any content differs.
func TestLayerPlanDigest(t *testing.T) {
	ctx := t.Context()
	digests := func(fx planFixture) [][sha256.Size]byte {
		t.Helper()
		plans, _, err := planLayers(ctx, fx.fsys, fx.groups, fx.pkgToDiff)
		if err != nil {
			t.Fatal(err)
		}
		var out [][sha256.Size]byte
		for _, p := range plans {
			d, err := p.Digest()
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, d)
		}
		return out
	}
	base := digests(newPlanFixture(t))
	if diff := cmp.Diff(base, digests(newPlanFixture(t))); diff != "" {
		t.Errorf("the same build planned different digests (-first +second):\n%s", diff)
	}

	fx := newPlanFixture(t)
	if err := fx.fsys.WriteFile("etc/passwd", []byte("root:x:0:0:root:/root:/bin/ash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed := digests(fx)
	if changed[2] == base[2] {
		t.Error("top layer: the same digest with different etc/passwd content")
	}

	// Entries are copies: changing one changes nothing about the plan.
	fresh := newPlanFixture(t)
	plans, _, err := planLayers(ctx, fresh.fsys, fresh.groups, fresh.pkgToDiff)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range plans[0].Entries() {
		if e.Header.PAXRecords != nil {
			e.Header.PAXRecords["SCHILY.xattr.user.changed"] = "1"
		}
	}
	if d, err := plans[0].Digest(); err != nil || d != base[0] {
		t.Errorf("layer 0 digest after changing its Entries = %x, %v; want %x", d, err, base[0])
	}
}
