package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/stretchr/testify/require"
)

func TestIntegrationMinIOPersistenceAndPrefixIsolation(t *testing.T) {
	endpoint := os.Getenv("MINIO_INTEGRATION_ENDPOINT")
	if endpoint == "" {
		t.Skip("MINIO_INTEGRATION_ENDPOINT is set by make test-integration")
	}
	accessKey := os.Getenv("MINIO_INTEGRATION_ACCESS_KEY")
	secretKey := os.Getenv("MINIO_INTEGRATION_SECRET_KEY")
	require.NotEmpty(t, accessKey)
	require.NotEmpty(t, secretKey)
	client, err := minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4(accessKey, secretKey, "")})
	require.NoError(t, err)
	bucket := "auth-master-" + uuid.NewString()
	store := minioStore{client: client, bucket: bucket}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	require.NoError(t, store.Ensure(ctx))
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		for object := range client.ListObjects(cleanupCtx, bucket, minio.ListObjectsOptions{Recursive: true}) {
			if object.Err == nil {
				_ = client.RemoveObject(cleanupCtx, bucket, object.Key, minio.RemoveObjectOptions{})
			}
		}
		_ = client.RemoveBucket(cleanupCtx, bucket)
	})

	owner := uuid.NewString()
	other := uuid.NewString()
	require.NoError(t, store.CreateFolder(ctx, owner))
	require.NoError(t, store.Put(ctx, owner+"/note.txt", bytes.NewBufferString("persistent"), 10, "text/plain"))
	require.NoError(t, store.CreateFolder(ctx, owner+"/projects"))
	require.NoError(t, store.Put(ctx, owner+"/projects/brief.txt", bytes.NewBufferString("brief"), 5, "text/plain"))
	require.NoError(t, store.Put(ctx, owner+"/empty.txt", bytes.NewReader(nil), 0, "text/plain"))
	rootEntries, err := store.List(ctx, owner)
	require.NoError(t, err)
	require.Len(t, rootEntries, 3)
	require.Equal(t, []storageEntry{
		{Name: "projects", Kind: "folder"},
		{Name: "empty.txt", Kind: "file", LastModified: rootEntries[1].LastModified},
		{Name: "note.txt", Kind: "file", Size: 10, LastModified: rootEntries[2].LastModified},
	}, rootEntries, "listing must be immediate-child-only and hide .keep")
	projectEntries, err := store.List(ctx, owner+"/projects")
	require.NoError(t, err)
	require.Len(t, projectEntries, 1)
	require.Equal(t, "brief.txt", projectEntries[0].Name)
	require.Equal(t, "file", projectEntries[0].Kind)

	secondClient, err := minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4(accessKey, secretKey, "")})
	require.NoError(t, err)
	marker, err := (minioStore{client: secondClient, bucket: bucket}).Get(ctx, owner+"/.keep")
	require.NoError(t, err)
	markerContent, err := io.ReadAll(marker.Body)
	require.NoError(t, err)
	require.NoError(t, marker.Body.Close())
	require.Empty(t, markerContent)
	persisted, err := (minioStore{client: secondClient, bucket: bucket}).Get(ctx, owner+"/note.txt")
	require.NoError(t, err)
	defer persisted.Body.Close()
	content, err := io.ReadAll(persisted.Body)
	require.NoError(t, err)
	require.Equal(t, "persistent", string(content))
	require.Equal(t, "text/plain", persisted.ContentType)
	_, err = store.Get(ctx, other+"/note.txt")
	require.True(t, errors.Is(err, errObjectNotFound), "a different user prefix must not resolve the object")
}
