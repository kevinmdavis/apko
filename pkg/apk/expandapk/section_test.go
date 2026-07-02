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

package expandapk

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/expandapk/tarfs"
)

// bytesSection is a Section backed by an in-memory byte slice.
type bytesSection struct {
	data []byte
}

var _ Section = (*bytesSection)(nil)

func (s *bytesSection) Open() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(s.data)), nil
}

func (s *bytesSection) Size() int64 {
	return int64(len(s.data))
}

// tarGz builds a tar archive from files in memory, returning both the
// gzip-compressed and uncompressed bytes.
func tarGz(t *testing.T, files map[string]string) (compressed, uncompressed []byte) {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, content := range files {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(content)),
		}))
		_, err := tw.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())

	var gzBuf bytes.Buffer
	gzw := gzip.NewWriter(&gzBuf)
	_, err := gzw.Write(buf.Bytes())
	require.NoError(t, err)
	require.NoError(t, gzw.Close())

	return gzBuf.Bytes(), buf.Bytes()
}

// TestInMemoryAPKExpanded exercises an APKExpanded constructed entirely from
// in-memory Sections and tarfs instances, with none of the path fields set,
// proving that no filesystem access is required.
func TestInMemoryAPKExpanded(t *testing.T) {
	sigGz, _ := tarGz(t, map[string]string{
		".SIGN.RSA.fake.rsa.pub": "not a real signature",
	})
	ctlGz, ctlTar := tarGz(t, map[string]string{
		".PKGINFO": "pkgname = test\npkgver = 1.0.0-r0\n",
	})
	pkgGz, pkgTar := tarGz(t, map[string]string{
		"usr/bin/hello": "hello, world",
	})

	controlFS, err := tarfs.New(bytes.NewReader(ctlTar), int64(len(ctlTar)))
	require.NoError(t, err)
	tarFS, err := tarfs.New(bytes.NewReader(pkgTar), int64(len(pkgTar)))
	require.NoError(t, err)

	exp := &APKExpanded{
		Signed:    true,
		Signature: &bytesSection{data: sigGz},
		Control:   &bytesSection{data: ctlGz},
		Package:   &bytesSection{data: pkgGz},
		ControlFS: controlFS,
		TarFS:     tarFS,
	}

	t.Run("ControlData", func(t *testing.T) {
		got, err := exp.ControlData()
		require.NoError(t, err)
		require.Equal(t, ctlTar, got)
	})

	t.Run("PkgInfo", func(t *testing.T) {
		got, err := exp.PkgInfo()
		require.NoError(t, err)
		require.Equal(t, "test", got.Name)
		require.Equal(t, "1.0.0-r0", got.Version)
	})

	t.Run("APK", func(t *testing.T) {
		rc, err := exp.APK()
		require.NoError(t, err)
		got, err := io.ReadAll(rc)
		require.NoError(t, err)
		require.NoError(t, rc.Close())

		require.Equal(t, slices.Concat(sigGz, ctlGz, pkgGz), got)
	})

	t.Run("APK unsigned skips nil Signature", func(t *testing.T) {
		unsigned := &APKExpanded{
			Control: &bytesSection{data: ctlGz},
			Package: &bytesSection{data: pkgGz},
		}

		rc, err := unsigned.APK()
		require.NoError(t, err)
		got, err := io.ReadAll(rc)
		require.NoError(t, err)
		require.NoError(t, rc.Close())

		require.Equal(t, slices.Concat(ctlGz, pkgGz), got)
	})

	t.Run("IsValid uses Validate hook", func(t *testing.T) {
		valid := true
		called := 0
		exp.Validate = func() bool {
			called++
			return valid
		}

		require.True(t, exp.IsValid())
		valid = false
		require.False(t, exp.IsValid())
		require.Equal(t, 2, called)
	})

	t.Run("Close uses Cleanup hook", func(t *testing.T) {
		wantErr := errors.New("cleanup failed")
		called := 0
		exp.Cleanup = func() error {
			called++
			return wantErr
		}

		require.ErrorIs(t, exp.Close(), wantErr)
		require.Equal(t, 1, called)
	})
}

func TestFileSection(t *testing.T) {
	want := make([]byte, 1024)
	_, err := rand.Read(want)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "section.tar.gz")
	require.NoError(t, os.WriteFile(path, want, 0o644))

	s, err := NewFileSection(path)
	require.NoError(t, err)

	require.Equal(t, int64(len(want)), s.Size())

	rc, err := s.Open()
	require.NoError(t, err)
	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())
	require.Equal(t, want, got)

	pather, ok := s.(interface{ Path() string })
	require.True(t, ok, "file-backed Section should unwrap to a Path() string")
	require.Equal(t, path, pather.Path())

	_, err = NewFileSection(filepath.Join(t.TempDir(), "does-not-exist"))
	require.Error(t, err)
}

// TestExpandApkPopulatesSections verifies that ExpandApk populates the
// Section fields consistently with the path fields: same paths, same sizes,
// and the same bytes readable both ways.
func TestExpandApkPopulatesSections(t *testing.T) {
	f, err := os.Open("testdata/hello-wolfi-2.12.1-r0.apk")
	require.NoError(t, err)
	defer f.Close()

	exp, err := ExpandApk(t.Context(), f, t.TempDir())
	require.NoError(t, err)
	defer exp.Close()

	require.Nil(t, exp.Validate)
	require.Nil(t, exp.Cleanup)

	for _, tt := range []struct {
		name     string
		section  Section
		path     string
		wantSize int64
	}{
		{"signature", exp.Signature, exp.SignatureFile, exp.SignatureSize},
		{"control", exp.Control, exp.ControlFile, exp.ControlSize},
		{"package", exp.Package, exp.PackageFile, exp.PackageSize},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.NotNil(t, tt.section)
			require.Equal(t, tt.wantSize, tt.section.Size())

			pather, ok := tt.section.(interface{ Path() string })
			require.True(t, ok, "expanded Section should unwrap to a Path() string")
			require.Equal(t, tt.path, pather.Path())

			want, err := os.ReadFile(tt.path)
			require.NoError(t, err)
			require.Equal(t, int64(len(want)), tt.section.Size())

			rc, err := tt.section.Open()
			require.NoError(t, err)
			got, err := io.ReadAll(rc)
			require.NoError(t, err)
			require.NoError(t, rc.Close())
			require.Equal(t, want, got)
		})
	}
}
