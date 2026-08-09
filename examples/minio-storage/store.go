package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
)

var errObjectNotFound = errors.New("object not found")

type storedObject struct {
	Body        io.ReadCloser
	Size        int64
	ContentType string
}

type storageEntry struct {
	Name         string     `json:"name"`
	Path         string     `json:"path"`
	Kind         string     `json:"kind"`
	Size         int64      `json:"size"`
	LastModified *time.Time `json:"last_modified,omitempty"`
}

type objectStore interface {
	Ensure(context.Context) error
	CreateFolder(context.Context, string) error
	List(context.Context, string) ([]storageEntry, error)
	Put(context.Context, string, io.Reader, int64, string) error
	Get(context.Context, string) (storedObject, error)
}

type minioStore struct {
	client *minio.Client
	bucket string
}

func (s minioStore) Ensure(ctx context.Context) error {
	exists, err := s.client.BucketExists(ctx, s.bucket)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return s.client.MakeBucket(ctx, s.bucket, minio.MakeBucketOptions{})
}

func (s minioStore) CreateFolder(ctx context.Context, prefix string) error {
	return s.Put(ctx, prefix+"/.keep", bytes.NewReader(nil), 0, "application/octet-stream")
}

func (s minioStore) List(ctx context.Context, prefix string) ([]storageEntry, error) {
	prefix = strings.Trim(prefix, "/") + "/"
	entries := make([]storageEntry, 0)
	seenFolders := make(map[string]struct{})
	for info := range s.client.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: false}) {
		if info.Err != nil {
			return nil, info.Err
		}
		relative := strings.TrimPrefix(info.Key, prefix)
		if relative == "" || relative == ".keep" {
			continue
		}
		if strings.HasSuffix(relative, "/") || strings.Contains(relative, "/") {
			name := strings.TrimSuffix(strings.SplitN(relative, "/", 2)[0], "/")
			if name == "" {
				continue
			}
			if _, exists := seenFolders[name]; !exists {
				seenFolders[name] = struct{}{}
				entries = append(entries, storageEntry{Name: name, Kind: "folder"})
			}
			continue
		}
		modified := info.LastModified
		entries = append(entries, storageEntry{Name: relative, Kind: "file", Size: info.Size, LastModified: &modified})
	}
	sortStorageEntries(entries)
	return entries, nil
}

func sortStorageEntries(entries []storageEntry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Kind != entries[j].Kind {
			return entries[i].Kind == "folder"
		}
		left := strings.ToLower(entries[i].Name)
		right := strings.ToLower(entries[j].Name)
		if left == right {
			return entries[i].Name < entries[j].Name
		}
		return left < right
	})
}

func (s minioStore) Put(ctx context.Context, key string, reader io.Reader, size int64, contentType string) error {
	_, err := s.client.PutObject(ctx, s.bucket, key, reader, size, minio.PutObjectOptions{ContentType: contentType})
	return err
}

func (s minioStore) Get(ctx context.Context, key string) (storedObject, error) {
	info, err := s.client.StatObject(ctx, s.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		response := minio.ToErrorResponse(err)
		if response.Code == "NoSuchKey" || response.Code == "NoSuchObject" || response.StatusCode == 404 {
			return storedObject{}, errObjectNotFound
		}
		return storedObject{}, err
	}
	object, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return storedObject{}, err
	}
	if object == nil {
		return storedObject{}, fmt.Errorf("MinIO returned a nil object")
	}
	return storedObject{Body: object, Size: info.Size, ContentType: info.ContentType}, nil
}
