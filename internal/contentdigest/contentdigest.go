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

// Package contentdigest names content by its SHA-256, spelled
// "sha256:<hex>", for the content nothing else names a digest for.
package contentdigest

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
)

// Of is the digest of what r reads, to its end.
func Of(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return spell(h.Sum(nil)), nil
}

// OfBytes is the digest of b.
func OfBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return spell(sum[:])
}

func spell(sum []byte) string { return "sha256:" + hex.EncodeToString(sum) }
