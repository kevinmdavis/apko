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
	"debug/elf"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	erofs "github.com/erofs/go-erofs"
	"github.com/stretchr/testify/require"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/elfmeta"
	"chainguard.dev/apko/pkg/options"
)

const stampedLib = "usr/lib/libx.so.1"

// TestLayerFSElfmetaStamps checks that tar and EROFS layers retain stamps by
// default and omit them when requested, preserving other xattrs and stamps
// in the build filesystem.
func TestLayerFSElfmetaStamps(t *testing.T) {
	stamp := elfmeta.Info{Dyn: true, Machine: elf.EM_X86_64, Sonames: []string{"libx.so.1"}}.Encode()

	for _, tc := range []struct {
		name string
		omit bool
	}{{"default", false}, {"omitted", true}} {
		omit := tc.omit
		t.Run(tc.name, func(t *testing.T) {
			fsys := apkfs.NewMemFS()
			require.NoError(t, fsys.MkdirAll("usr/lib", 0o755))
			require.NoError(t, fsys.WriteFile(stampedLib, []byte("\x7fELF"), 0o755))
			require.NoError(t, fsys.SetXattr(stampedLib, elfmeta.Xattr, stamp))
			require.NoError(t, fsys.SetXattr(stampedLib, "user.kept", []byte("yes")))

			bc := &Context{fs: fsys, o: options.Options{OmitElfmetaStamps: omit}}
			want := map[string]string{"user.kept": "yes"}
			if !omit {
				want[elfmeta.Xattr] = string(stamp)
			}

			// Tar layers.
			got := map[string]string{}
			found := false
			for f, err := range walkFS(t.Context(), bc.layerFS()) {
				require.NoError(t, err)
				if f.path != stampedLib {
					continue
				}
				found = true
				for k, v := range f.header.PAXRecords {
					if name, ok := strings.CutPrefix(k, xattrTarPAXRecordsPrefix); ok {
						got[name] = v
					}
				}
			}
			require.True(t, found, "walkFS did not reach %s", stampedLib)
			require.Equal(t, want, got, "tar xattrs")

			// EROFS layers.
			out := filepath.Join(t.TempDir(), "image.erofs")
			f, err := os.Create(out)
			require.NoError(t, err)
			require.NoError(t, writeErofs(t.Context(), f, bc.layerFS(), t.TempDir(), epoch))
			require.NoError(t, f.Close())
			r, err := os.Open(out)
			require.NoError(t, err)
			defer r.Close()
			img, err := erofs.Open(r)
			require.NoError(t, err)
			info, err := fs.Stat(img, stampedLib)
			require.NoError(t, err)
			st, ok := info.Sys().(*erofs.Stat)
			require.True(t, ok)
			require.Equal(t, want, st.Xattrs, "erofs xattrs")

			// The build filesystem keeps the stamp either way.
			b, err := fsys.GetXattr(stampedLib, elfmeta.Xattr)
			require.NoError(t, err)
			require.Equal(t, stamp, b)
		})
	}
}
