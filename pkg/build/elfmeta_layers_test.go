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
	"testing"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/elfmeta"
)

// TestWalkFSKeepsElfmetaOutOfLayers checks that a file's elfmeta stamp,
// which the ld.so cache reads while building, is not written into the tar
// headers of the layers, while its other xattrs are.
func TestWalkFSKeepsElfmetaOutOfLayers(t *testing.T) {
	fsys := apkfs.NewMemFS()
	if err := fsys.MkdirAll("usr/lib", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fsys.WriteFile("usr/lib/libx.so.1", []byte("\x7fELF"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fsys.SetXattr("usr/lib/libx.so.1", elfmeta.Xattr, []byte("stamp")); err != nil {
		t.Fatal(err)
	}
	if err := fsys.SetXattr("usr/lib/libx.so.1", "user.kept", []byte("yes")); err != nil {
		t.Fatal(err)
	}
	found := false
	for f, err := range walkFS(t.Context(), fsys) {
		if err != nil {
			t.Fatal(err)
		}
		if f.path != "usr/lib/libx.so.1" {
			continue
		}
		found = true
		if _, ok := f.header.PAXRecords[xattrTarPAXRecordsPrefix+elfmeta.Xattr]; ok {
			t.Error("the elfmeta stamp was written into the layer")
		}
		if got := f.header.PAXRecords[xattrTarPAXRecordsPrefix+"user.kept"]; got != "yes" {
			t.Errorf("user.kept = %q, want it kept", got)
		}
	}
	if !found {
		t.Fatal("walkFS did not reach usr/lib/libx.so.1")
	}
}
