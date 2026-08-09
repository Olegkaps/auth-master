package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSortStorageEntriesIsStableAcrossCaseCollisions(t *testing.T) {
	entries := []storageEntry{
		{Name: "a.txt", Kind: "file"},
		{Name: "Zoo", Kind: "folder"},
		{Name: "A.txt", Kind: "file"},
		{Name: "alpha", Kind: "folder"},
	}

	sortStorageEntries(entries)

	require.Equal(t, []string{"alpha", "Zoo", "A.txt", "a.txt"}, []string{
		entries[0].Name,
		entries[1].Name,
		entries[2].Name,
		entries[3].Name,
	})
}
