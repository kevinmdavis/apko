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
	"maps"
	"os"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/elfmeta"
)

// layerFS returns the filesystem for image layers, omitting elfmeta stamps
// when requested while preserving them in the build filesystem.
func (bc *Context) layerFS() apkfs.FullFS {
	if bc.o.OmitElfmetaStamps {
		return withoutElfmetaStamps{bc.fs}
	}
	return bc.fs
}

// withoutElfmetaStamps hides elfmeta stamps from xattr reads and listings
// without changing the underlying filesystem or other xattrs.
type withoutElfmetaStamps struct {
	apkfs.FullFS
}

func (f withoutElfmetaStamps) GetXattr(path string, attr string) ([]byte, error) {
	if attr == elfmeta.Xattr {
		return nil, os.ErrNotExist
	}
	return f.FullFS.GetXattr(path, attr)
}

func (f withoutElfmetaStamps) ListXattrs(path string) (map[string][]byte, error) {
	xattrs, err := f.FullFS.ListXattrs(path)
	if _, ok := xattrs[elfmeta.Xattr]; ok {
		xattrs = maps.Clone(xattrs)
		delete(xattrs, elfmeta.Xattr)
	}
	return xattrs, err
}
