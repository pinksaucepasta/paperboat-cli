package serve

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	DefaultDiscoveryLimit = 10000
	DefaultDiscoveryDepth = 12
)

func DiscoverSources(ctx context.Context, root string, limit, maxDepth int) ([]Source, error) {
	if ctx == nil || limit < 1 || maxDepth < 0 {
		return nil, ErrInvalidSource
	}
	rootSource, err := ResolveSource(root)
	if err != nil || rootSource.Kind != SourceDirectory {
		return nil, err
	}
	type pendingDirectory struct {
		path  string
		depth int
	}
	queue := []pendingDirectory{{path: rootSource.Path}}
	result := []Source{rootSource}
	for len(queue) > 0 && len(result) < limit {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		current := queue[0]
		queue = queue[1:]
		if current.depth >= maxDepth {
			continue
		}
		entries, readErr := os.ReadDir(current.path)
		if readErr != nil {
			continue
		}
		for _, entry := range entries {
			if len(result) >= limit {
				break
			}
			name := entry.Name()
			if strings.HasPrefix(name, ".") || entry.Type()&os.ModeSymlink != 0 || entry.IsDir() && (name == "node_modules" || name == "vendor") {
				continue
			}
			candidate, resolveErr := ResolveSource(filepath.Join(current.path, name))
			if resolveErr != nil {
				continue
			}
			result = append(result, candidate)
			if candidate.Kind == SourceDirectory {
				queue = append(queue, pendingDirectory{path: candidate.Path, depth: current.depth + 1})
			}
		}
	}
	sort.Slice(result[1:], func(i, j int) bool { return result[i+1].Path < result[j+1].Path })
	return result, nil
}
