package main

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRoleNamesAndStorageTags(t *testing.T) {
	require.Equal(t, "storage.folder."+testUserID, folderRole(testUserID))
	require.Equal(t, folderRole(testUserID), folderRoleForPath(testUserID, ""))
	require.Equal(t, folderRole(testUserID)+".3a1f946d22911c17fa2f48ad4a2a41da", folderRoleForPath(testUserID, "projects/private"))
	require.NotEqual(t, folderRoleForPath(testUserID, "projects/private"), folderRoleForPath(testUserID, "projects/sibling"))
	require.Equal(t, "projects", parentFolder("projects/private"))
	require.Equal(t, "", parentFolder("projects"))
	role, err := groupRole("Shared-Team")
	require.NoError(t, err)
	require.Equal(t, "storage.group.shared-team", role)
	_, err = groupRole("../unsafe")
	require.Error(t, err)
	require.NoError(t, validateTags([]string{"read", "write", "admin"}))
	err = validateTags([]string{"owner"})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}
