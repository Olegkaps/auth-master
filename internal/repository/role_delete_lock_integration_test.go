package repository

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestIntegration_DeleteRoleParticipatesInHierarchyLock(t *testing.T) {
	s, cleanup := setupRepo(t)
	defer cleanup()
	ctx := context.Background()
	parent, err := s.CreateRole(ctx, "delete-parent", "", nil)
	require.NoError(t, err)
	deleted, err := s.CreateRole(ctx, "delete-target", "", &parent)
	require.NoError(t, err)
	child, err := s.CreateRole(ctx, "delete-child", "", &deleted)
	require.NoError(t, err)

	holder := s.db.Begin()
	require.NoError(t, holder.Error)
	require.NoError(t, lockRoleHierarchy(holder))
	done := make(chan error, 1)
	go func() { done <- s.DeleteRole(ctx, deleted) }()
	select {
	case err := <-done:
		require.Failf(t, "delete did not wait for hierarchy lock", "returned early: %v", err)
	case <-time.After(150 * time.Millisecond):
		// The deterministic lock holder still owns the hierarchy write lock.
	}
	require.NoError(t, holder.Commit().Error)
	require.NoError(t, <-done)

	removed, err := s.GetRoleByID(ctx, deleted)
	require.NoError(t, err)
	require.Nil(t, removed)
	childRole, err := s.GetRoleByID(ctx, child)
	require.NoError(t, err)
	require.NotNil(t, childRole)
	require.Len(t, childRole.ParentIDs, 1)
	require.Equal(t, []string{parent.String()}, []string{childRole.ParentIDs[0].String()}, "child must be reparented before the target is removed")
	var orphanEdges int64
	require.NoError(t, s.db.Model(&roleMountModel{}).
		Where("child_role_id = ? OR parent_role_id = ?", deleted, deleted).Count(&orphanEdges).Error)
	require.Zero(t, orphanEdges)
	require.Error(t, s.MountRole(ctx, child, deleted), "a concurrent or later edge cannot reference the deleted role")
}
