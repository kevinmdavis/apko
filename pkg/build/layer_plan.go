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
	"path"
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

// planner collects one layer's entries, and keeps the directory stack that
// tells it which parent directories the layer has yet to hold.
type planner struct {
	dirStack
	plan *LayerPlan
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

func (pl *planner) add(f *file) {
	if hasContent(f.header) {
		pl.files = append(pl.files, plannedFile{index: len(pl.plan.entries), path: f.path, info: f.info})
	}
	pl.plan.entries = append(pl.plan.entries, PlanEntry{Header: *f.header})
}

// planLayers partitions the walk of fsys into one layer per group plus a top
// layer. Each entry is planned with its header as it is at that moment, so
// the directories a layer repeats keep the mtime they are planned with.
func planLayers(ctx context.Context, fsys apkfs.FullFS, groups []*group, pkgToDiff map[*apk.Package][]byte) ([]*LayerPlan, *buildSource, error) {
	src := &buildSource{fsys: fsys, paths: map[string]string{}, inline: map[string][]byte{}}
	var planners []*planner
	newPlanner := func(pkgs []*apk.Package) *planner {
		pl := &planner{plan: &LayerPlan{packages: pkgs}}
		planners = append(planners, pl)
		return pl
	}

	// A planner for each layer, and a map to quickly find it given a package or group.
	packageToPlanner := map[string]*planner{}
	groupToPlanner := map[*group]*planner{}
	for _, g := range groups {
		pl := newPlanner(slices.Clone(g.pkgs))
		groupToPlanner[g] = pl
		for _, pkg := range g.pkgs {
			packageToPlanner[pkg.Name] = pl
		}
	}

	// The top layer holds anything that doesn't belong to a package.
	top := newPlanner(nil)

	// In a tar file, it is customary to include directories before files in those directories.
	// In order to know which directories we need to include, we maintain a directory stack for each layer.
	// We compare those stacks to the full FS that we're walking whenever we plan a new tar entry.
	// If the main stack doesn't match the layer's stack, we update the layer's stack and add
	// any missing directory entries to the layer before we plan the actual file entry.
	stack := []*file{}

	for f, err := range walkFS(ctx, fsys) {
		if err != nil {
			return nil, nil, err
		}

		// Maintain our "main" stack.
		if f.header.Typeflag == tar.TypeDir {
			// Pop off any directories that are not parents of the current file's directory.
			for i, v := range slices.Backward(stack) {
				if v.path == path.Dir(f.path) {
					break
				}

				stack = stack[:i]
			}

			// Push the current file onto the stack.
			stack = append(stack, f)
		}

		// By default, all files go into the top layer.
		pl := top

		// However, if a file implements an extension interface that tells us what package owns it,
		// we can use that to determine which layer it belongs to (if any).
		if pkger, ok := f.info.(interface {
			Package() *apk.Package
		}); ok {
			if pkg := pkger.Package(); pkg != nil {
				pl, ok = packageToPlanner[pkg.Name]
				if !ok {
					return nil, nil, fmt.Errorf("no layer for package %q, which owns %s", pkg.Name, f.path)
				}
			}
		}

		// As described above, bring the layer's stack up to date with the main stack.
		for _, todo := range pl.alignStacks(stack) {
			// We need to plan any missing directories returned by alignStacks.
			// But sometimes the result of alignStacks will include the file we're
			// about to plan (f) after this loop. In those cases, make sure we
			// don't plan it twice by skipping over it here.
			if todo.header == f.header {
				continue
			}

			// This is a little weird, but bear with me...
			// Often, multiple packages (and thus layers) contain files in the same directory.
			// The directories in each package likely have different timestamps.
			// The overall image's filesystem will only have one directory entry, so there
			// will be a "winner" timestamp that actually ends up in the image.
			// Unfortunately, this means that we don't get great layer deduplication
			// in a lot of situations, and the timestamp of some directories in any given
			// layer are influenced by the timestamp of directories in _other_ layers.
			// Since timestamps almost never have an observable effect on the image behavior,
			// and the "real" timestamp will end up in the "top" layer anyway and overwrite
			// the directory metadata for these package-ful layers, we can improve deduplication
			// without having any real effect on the image by overwriting this directory's
			// timestamp with the timestamp of the "f" file we're about to plan for this layer.
			todo.header.ModTime = f.header.ModTime

			pl.add(todo)
		}

		// Now we're back to normal tar stuff.
		pl.add(f)

		if f.header.Name == installedDB {
			// Add a partial installed db to each layer to satisfy scanners.
			for _, g := range groups {
				pl := groupToPlanner[g]

				// Make sure we have all parent directories to appease AWS Lambda.
				for _, todo := range pl.alignStacks(stack) {
					todo.header.ModTime = f.header.ModTime
					pl.add(todo)
				}

				// Accumulate all the idb entries for this layer.
				var buf bytes.Buffer
				for _, pkg := range g.pkgs {
					buf.Write(pkgToDiff[pkg])
				}

				// Only the size should be different across layers.
				idb := *f.header
				idb.Size = int64(buf.Len())

				data := buf.Bytes()
				d := contentdigest.OfBytes(data)
				pl.plan.entries = append(pl.plan.entries, PlanEntry{Header: idb, Digest: d})
				src.inline[d] = data
			}
		}
	}

	if err := digestFiles(ctx, fsys, planners, src); err != nil {
		return nil, nil, err
	}

	plans := make([]*LayerPlan, 0, len(groups)+1)
	for _, g := range groups {
		plans = append(plans, groupToPlanner[g].plan)
	}
	return append(plans, top.plan), src, nil
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

// dirStack is the stack of directories a layer has written so far, along the
// path of the walk.
type dirStack struct {
	stack []*file
}
