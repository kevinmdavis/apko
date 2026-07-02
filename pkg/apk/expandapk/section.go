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
	"fmt"
	"io"
	"os"
)

// Section provides access to one of an APK's gzip-compressed tar streams
// (signature, control, or package data) without prescribing where the bytes
// are stored.
type Section interface {
	// Open returns a reader over the section's compressed (tar.gz) bytes.
	// The caller is responsible for closing it.
	Open() (io.ReadCloser, error)

	// Size returns the size in bytes of the section's compressed contents.
	Size() int64
}

// fileSection is a Section backed by a file on disk. Its size is captured
// once at construction.
type fileSection struct {
	path string
	size int64
}

var _ Section = (*fileSection)(nil)

// NewFileSection returns a Section backed by the file at path, stat-ing it
// once to capture its size.
func NewFileSection(path string) (Section, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", path, err)
	}
	return &fileSection{path: path, size: info.Size()}, nil
}

func (s *fileSection) Open() (io.ReadCloser, error) {
	return os.Open(s.path)
}

func (s *fileSection) Size() int64 {
	return s.size
}

// Path returns the path of the backing file. Callers that need a real file
// path can unwrap a Section by asserting it to interface{ Path() string }.
func (s *fileSection) Path() string {
	return s.path
}
