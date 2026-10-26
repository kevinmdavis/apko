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
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"maps"
	"runtime"
	"slices"
	"sync"

	"golang.org/x/sync/errgroup"

	"chainguard.dev/apko/internal/contentdigest"
	"chainguard.dev/apko/pkg/apk/apk"
	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/build/types"
)

// installedDB is where apk keeps its installed database, which every package
// layer also gets its own slice of.
const installedDB = "usr/lib/apk/db/installed"

// planVersion leads every plan's encoding. Bump it with any change to the
// bytes Render writes for the same plan, or to the encoding itself, so that a
// plan's Digest names one layer.
const planVersion = "apko layer plan/1"

// LayerPlan is one layer of a multi-layer build, planned but not yet written:
// its tar entries, in order, each regular file's content named by digest.
// It holds no content; Render writes it from a ContentSource. Its Digest
// names the gzipped layer Render writes for it, byte for byte.
type LayerPlan struct {
	packages []*apk.Package
	entries  []PlanEntry
}

// PlanEntry is one tar entry of a plan: the header Render writes, exactly,
// and for a regular file with content, the content's digest, spelled
// "<algorithm>:<hex>": the one the build filesystem names it by (tarfs's
// is the package contents' digest while the file is unmodified, and its
// SHA-256 otherwise), or the SHA-256 of content planning made itself.
type PlanEntry struct {
	Header tar.Header
	Digest string
}

// Packages are the packages whose files the layer holds, in install order.
// The top layer, which holds everything no package owns, has none.
func (p *LayerPlan) Packages() []*apk.Package { return slices.Clone(p.packages) }

// Entries are the layer's entries, in the order Render writes them. They are
// the caller's to keep; changing them changes nothing about the plan.
func (p *LayerPlan) Entries() []PlanEntry {
	out := make([]PlanEntry, len(p.entries))
	for i, e := range p.entries {
		e.Header.PAXRecords = maps.Clone(e.Header.PAXRecords)
		out[i] = e
	}
	return out
}

// Digest is the SHA-256 of the plan's encoding: planVersion, then each
// entry's header (as archive/tar writes it) and digest, every field
// length-prefixed. Plans with the same Digest render the
// same bytes, given the same archive/tar and pgzip.
func (p *LayerPlan) Digest() (d [sha256.Size]byte, _ error) {
	h := sha256.New()
	field(h, []byte(planVersion))
	var hdrBuf bytes.Buffer
	for i := range p.entries {
		e := &p.entries[i]
		hdrBuf.Reset()
		// WriteHeader writes the header's blocks, PAX records included, as it
		// is called; the content it then expects is never written here.
		if err := tar.NewWriter(&hdrBuf).WriteHeader(&e.Header); err != nil {
			return d, fmt.Errorf("encoding header %s: %w", e.Header.Name, err)
		}
		field(h, hdrBuf.Bytes())
		field(h, []byte(e.Digest))
	}
	h.Sum(d[:0])
	return d, nil
}

// field writes b to h length-prefixed, so no two sequences of fields hash
// alike.
func field(h hash.Hash, b []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	h.Write(n[:])
	h.Write(b)
}

// ContentSource opens content by digest, serving the bytes the digest names.
// A digest it does not serve is an error wrapping fs.ErrNotExist.
type ContentSource interface {
	Open(ctx context.Context, digest string) (io.ReadCloser, error)
}

// buildSource is the build's own ContentSource: the build filesystem, by the
// path of a file each digest was planned from, and the content planning made
// itself. It trusts the build filesystem as BuildLayers does: a digest
// ContentDigest reported is the filesystem's to keep true, and so is content
// apko hashed while planning, which nothing changes before it is rendered.
type buildSource struct {
	fsys   apkfs.FullFS
	paths  map[string]string
	inline map[string][]byte
}

func (s *buildSource) Open(_ context.Context, digest string) (io.ReadCloser, error) {
	if b, ok := s.inline[digest]; ok {
		return io.NopCloser(bytes.NewReader(b)), nil
	}
	path, ok := s.paths[digest]
	if !ok {
		return nil, fmt.Errorf("no content for %s: %w", digest, fs.ErrNotExist)
	}
	f, err := s.fsys.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	return f, nil
}

// Render writes p's layer to w from src, gzipped, as an image holds it, and
// reports its digests.
func Render(ctx context.Context, p *LayerPlan, src ContentSource, w io.Writer) (*LayerDigests, error) {
	// pgzip's output depends on its block size alone, so this writes the
	// bytes BuildLayers' one-worker writers do.
	ls, err := newLayerStream(w, true, pgzipThreads)
	if err != nil {
		return nil, err
	}
	if err := p.writeEntries(ctx, ls.tw, src); err != nil {
		_, _ = ls.finish()
		return nil, err
	}
	d, err := ls.finish()
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func hasContent(hdr *tar.Header) bool {
	return hdr.Typeflag == tar.TypeReg && hdr.Size > 0
}

func (p *LayerPlan) writeEntries(ctx context.Context, tw *tar.Writer, src ContentSource) error {
	buf := make([]byte, 1<<20)
	for i := range p.entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		e := &p.entries[i]
		hdr := e.Header
		if err := tw.WriteHeader(&hdr); err != nil {
			return fmt.Errorf("writing header %s: %w", hdr.Name, err)
		}
		if !hasContent(&hdr) {
			continue
		}
		data, err := src.Open(ctx, e.Digest)
		if err != nil {
			return fmt.Errorf("%s: %w", hdr.Name, err)
		}
		_, err = io.CopyBuffer(tw, data, buf)
		// Should never fail in practice.
		cerr := data.Close()
		if err != nil {
			return fmt.Errorf("copying %s: %w", hdr.Name, err)
		}
		if cerr != nil {
			return fmt.Errorf("closing %s: %w", hdr.Name, cerr)
		}
	}
	return nil
}

// PlanLayers builds the image filesystem, as BuildLayers does for a layered
// configuration, and plans its layers without writing them: one per package
// group, then the top layer. It returns the build's source for their
// content, which reads the build filesystem and so lives as long as the
// build context, unchanged. Rendering every plan from it yields exactly the
// layers BuildLayers returns.
//
// It is for layered tar builds only; call it instead of BuildLayers, not as
// well as it. BuildLayers still writes layers with its own streaming writer,
// which TestRenderMatchesBuildLayers holds to Render, until it can render
// these plans instead.
func (bc *Context) PlanLayers(ctx context.Context) ([]*LayerPlan, ContentSource, error) {
	if bc.ic.Layering == nil || (bc.ic.Layering.Strategy == "" && bc.ic.Layering.Budget == 0) {
		return nil, nil, errors.New("planning layers needs a layered configuration")
	}
	if bc.ic.Format.Resolved() != types.LayerFormatTar {
		return nil, nil, fmt.Errorf("planning layers needs the %q layer format, not %q", types.LayerFormatTar, bc.ic.Format.Resolved())
	}
	groups, pkgToDiff, err := bc.layerGroups(ctx)
	if err != nil {
		return nil, nil, err
	}
	plans, src, err := planLayers(ctx, bc.fs, groups, pkgToDiff)
	if err != nil {
		return nil, nil, err
	}
	return plans, src, nil
}

// planner collects one layer's entries.
type planner struct {
	plan *LayerPlan
	src  *buildSource
	// files are the planned entries with content from the build filesystem,
	// by index, which digestFiles names.
	files []plannedFile
}

// plannedFile is an entry whose content is a file of the build filesystem.
type plannedFile struct {
	index int
	path  string
	info  fs.FileInfo
}

func (pl *planner) add(f *file) error {
	if hasContent(f.header) {
		pl.files = append(pl.files, plannedFile{index: len(pl.plan.entries), path: f.path, info: f.info})
	}
	pl.plan.entries = append(pl.plan.entries, PlanEntry{Header: *f.header})
	return nil
}

func (pl *planner) addData(hdr *tar.Header, data []byte) error {
	d := contentdigest.OfBytes(data)
	pl.plan.entries = append(pl.plan.entries, PlanEntry{Header: *hdr, Digest: d})
	pl.src.inline[d] = data
	return nil
}

// planLayers plans one layer per group, then the top layer, from the walk
// of fsys.
func planLayers(ctx context.Context, fsys apkfs.FullFS, groups []*group, pkgToDiff map[*apk.Package][]byte) ([]*LayerPlan, *buildSource, error) {
	src := &buildSource{fsys: fsys, paths: map[string]string{}, inline: map[string][]byte{}}
	planners := make([]*planner, 0, len(groups)+1)
	sinks := make([]layerSink, 0, len(groups)+1)
	newPlanner := func(pkgs []*apk.Package) {
		pl := &planner{plan: &LayerPlan{packages: pkgs}, src: src}
		planners = append(planners, pl)
		sinks = append(sinks, pl)
	}
	for _, g := range groups {
		newPlanner(slices.Clone(g.pkgs))
	}
	newPlanner(nil)
	if err := partitionLayers(ctx, fsys, groups, pkgToDiff, sinks); err != nil {
		return nil, nil, err
	}
	if err := digestFiles(ctx, fsys, planners, src); err != nil {
		return nil, nil, err
	}
	plans := make([]*LayerPlan, len(planners))
	for i, pl := range planners {
		plans[i] = pl.plan
	}
	return plans, src, nil
}

// digestFiles gives every planned file the digest of its content, naming
// each path once, in parallel, and records in src the path each digest is
// read from: the first planned with it.
func digestFiles(ctx context.Context, fsys apkfs.FullFS, planners []*planner, src *buildSource) error {
	var (
		mu      sync.Mutex
		digests = map[string]string{}
	)
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(runtime.GOMAXPROCS(0))
	queued := map[string]bool{}
	for _, pl := range planners {
		for _, f := range pl.files {
			if queued[f.path] {
				continue
			}
			queued[f.path] = true
			g.Go(func() error {
				d, err := fileDigest(gctx, fsys, f)
				if err != nil {
					return err
				}
				mu.Lock()
				digests[f.path] = d
				mu.Unlock()
				return nil
			})
		}
	}
	if err := g.Wait(); err != nil {
		return err
	}
	for _, pl := range planners {
		for _, f := range pl.files {
			d := digests[f.path]
			pl.plan.entries[f.index].Digest = d
			if _, ok := src.paths[d]; !ok {
				src.paths[d] = f.path
			}
		}
		pl.files = nil
	}
	return nil
}

// fileDigest names f's content as the build filesystem does, through its
// FileInfo's ContentDigest (tarfs names every file's), or else by its
// SHA-256, read through fsys.
func fileDigest(ctx context.Context, fsys apkfs.FullFS, f plannedFile) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if cd, ok := f.info.(interface{ ContentDigest() (string, error) }); ok {
		d, err := cd.ContentDigest()
		if err != nil {
			return "", fmt.Errorf("naming %s: %w", f.path, err)
		}
		if d != "" {
			return d, nil
		}
	}
	r, err := fsys.Open(f.path)
	if err != nil {
		return "", fmt.Errorf("opening %s: %w", f.path, err)
	}
	defer r.Close()
	d, err := contentdigest.Of(r)
	if err != nil {
		return "", fmt.Errorf("hashing %s: %w", f.path, err)
	}
	return d, nil
}
