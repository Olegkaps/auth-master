package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const testUserID = "70c4c1df-9ff6-4d0c-a7c4-2b4e693ff158"

func testStorageApp(checker *fakeChecker, provisioner *fakeProvisioner, store *fakeStore) storageApp {
	return storageApp{
		checker: checker, provisioner: provisioner, objects: store,
		service: serviceCredentials{login: "storage-service", secret: "Service-Secret1!"},
		pending: newPendingRegistrations(),
	}
}

func TestStoragePageIsAnExplorableTokenBasedWorkspace(t *testing.T) {
	app := testStorageApp(&fakeChecker{}, &fakeProvisioner{}, &fakeStore{}).routes()
	response := perform(app, http.MethodGet, "/", "", "")
	require.Equal(t, http.StatusOK, response.Code)
	body := response.Body.String()
	require.Contains(t, body, "<h1>MinIO storage workspace</h1>")
	require.Contains(t, body, "make -C examples token EXAMPLE=minio-storage PERSONA=owner")
	require.Contains(t, body, "new URLSearchParams(location.search)")
	require.NotContains(t, body, "Operator access token")
	require.NotContains(t, body, `data-testid="invite-token"`)
	for _, testID := range []string{
		"registration-card", "register-login", "register-email", "register-password", "register", "register-result",
		"workspace-card", "access-token", "owner-id", "open-root", "breadcrumbs", "folder-list", "folder-name",
		"create-folder", "file-input", "upload-file", "file-list", "refresh-access", "access-list", "share-group", "share-folder",
	} {
		require.Contains(t, body, `data-testid="`+testID+`"`)
	}
	require.Contains(t, body, `aria-live="polite"`)
}

func TestPublicRegistrationCreatesInviteRegistersAndProvisions(t *testing.T) {
	provisioner := &fakeProvisioner{}
	store := &fakeStore{}
	app := testStorageApp(&fakeChecker{}, provisioner, store).routes()
	response := perform(app, http.MethodPost, "/register", `{"login":"new-user","email":"new@test.dev","password":"Strong-Pass1!"}`, "")
	require.Equal(t, http.StatusCreated, response.Code)
	require.Contains(t, response.Body.String(), `"provisioning_status":"ready"`)
	require.NotContains(t, response.Body.String(), "Service-Secret1!")
	require.Equal(t, 1, provisioner.serviceTokens)
	require.Equal(t, []string{"service-jwt"}, provisioner.inviteTokens)
	require.Equal(t, "invite-token", provisioner.registration.InviteToken)
	require.Equal(t, []string{"service-jwt"}, provisioner.provisionTokens)
	require.Equal(t, []string{testUserID}, store.created)
}

func TestRegistrationProvisionFailureReturnsRetryablePendingState(t *testing.T) {
	provisioner := &fakeProvisioner{provisionFailures: 1}
	store := &fakeStore{}
	app := testStorageApp(&fakeChecker{}, provisioner, store).routes()
	response := perform(app, http.MethodPost, "/register", `{"login":"new-user","email":"new@test.dev","password":"Strong-Pass1!"}`, "")
	require.Equal(t, http.StatusAccepted, response.Code)
	require.Contains(t, response.Body.String(), `/registrations/`+testUserID+`/provision`)

	response = perform(app, http.MethodPost, "/registrations/11111111-1111-1111-1111-111111111111/provision", `{}`, "")
	require.Equal(t, http.StatusNotFound, response.Code, "arbitrary users must not be provisioned by the public retry route")

	response = perform(app, http.MethodPost, "/registrations/"+testUserID+"/provision", `{}`, "")
	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, 2, provisioner.serviceTokens, "each privileged attempt must mint a fresh service token")
	require.Equal(t, []string{testUserID}, store.created)
	response = perform(app, http.MethodPost, "/registrations/"+testUserID+"/provision", `{}`, "")
	require.Equal(t, http.StatusNotFound, response.Code)
}

func TestRegistrationRequiresConfiguredServiceIdentity(t *testing.T) {
	app := storageApp{checker: &fakeChecker{}, provisioner: &fakeProvisioner{}, objects: &fakeStore{}}.routes()
	response := perform(app, http.MethodPost, "/register", `{"login":"new-user","email":"new@test.dev","password":"Strong-Pass1!"}`, "")
	require.Equal(t, http.StatusServiceUnavailable, response.Code)
	require.Equal(t, `{"error":"storage provisioning service unavailable"}`+"\n", response.Body.String())
}

func TestFolderNavigationCreationAndSelectedAccessUseFolderRole(t *testing.T) {
	parent := "projects"
	checker := &fakeChecker{allowed: map[string]bool{
		folderRoleForPath(testUserID, parent) + "|admin": true,
	}}
	provisioner := &fakeProvisioner{access: folderAccess{Role: folderRoleForPath(testUserID, parent), Groups: []string{"readers"}}}
	store := &fakeStore{entries: []storageEntry{{Name: "child", Kind: "folder"}, {Name: "empty.txt", Kind: "file", Size: 0}, {Name: "brief.txt", Kind: "file", Size: 5}}}
	app := testStorageApp(checker, provisioner, store).routes()

	response := perform(app, http.MethodGet, "/folders/"+testUserID+"?path=projects", "", "owner")
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), `"path":"projects/brief.txt"`)
	require.Contains(t, response.Body.String(), `"name":"empty.txt","path":"projects/empty.txt","kind":"file","size":0`)
	require.NotContains(t, response.Body.String(), "0001-01-01")
	require.Equal(t, []string{testUserID + "/projects"}, store.listed)

	response = perform(app, http.MethodPost, "/folders/"+testUserID, `{"parent":"projects","name":"Q3 docs"}`, "owner")
	require.Equal(t, http.StatusCreated, response.Code)
	require.Equal(t, "projects/Q3 docs", provisioner.provisionedFolder)
	require.Equal(t, "service-jwt", provisioner.folderToken)
	require.Contains(t, store.created, testUserID+"/projects/Q3 docs")

	response = perform(app, http.MethodGet, "/folders/"+testUserID+"/access?path=projects", "", "owner")
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), `"readers"`)
	require.Equal(t, parent, provisioner.accessFolder)

	response = perform(app, http.MethodPost, "/folders/"+testUserID+"/access/groups/writers", `{"path":"projects"}`, "owner")
	require.Equal(t, http.StatusNoContent, response.Code)
	require.Equal(t, "projects", provisioner.sharedFolder)
	require.Equal(t, "writers", provisioner.sharedGroup)
	require.Equal(t, "owner", provisioner.sharedToken)
}

func TestShareForwardsHumanSoAuthMasterCanRequireGroupAuthority(t *testing.T) {
	checker := &fakeChecker{allowed: map[string]bool{folderRole(testUserID) + "|admin": true}}
	provisioner := &fakeProvisioner{shareError: status.Error(codes.PermissionDenied, "group authority required")}
	app := testStorageApp(checker, provisioner, &fakeStore{}).routes()
	response := perform(app, http.MethodPost, "/folders/"+testUserID+"/access/groups/unmanaged", `{"path":""}`, "folder-admin")
	require.Equal(t, http.StatusForbidden, response.Code)
	require.Equal(t, "folder-admin", provisioner.sharedToken)
	require.Zero(t, provisioner.serviceTokens)
}

func TestObjectAuthorizationUsesContainingFolderAndBoundedCanonicalPath(t *testing.T) {
	role := folderRoleForPath(testUserID, "projects/child")
	checker := &fakeChecker{allowed: map[string]bool{role + "|write": true, role + "|read": true}}
	store := &fakeStore{}
	appValue := testStorageApp(checker, &fakeProvisioner{}, store)
	appValue.maxUploadBytes = 4
	app := appValue.routes()

	response := perform(app, http.MethodPut, "/folders/"+testUserID+"/objects/projects/child/note.txt", "four", "writer")
	require.Equal(t, http.StatusNoContent, response.Code)
	require.Equal(t, []byte("four"), store.objects[testUserID+"/projects/child/note.txt"])
	require.Contains(t, checker.calls, role+"|write")

	response = perform(app, http.MethodGet, "/folders/"+testUserID+"/objects/projects/child/note.txt", "", "reader")
	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, "four", response.Body.String())
	require.Contains(t, checker.calls, role+"|read")

	response = perform(app, http.MethodPut, "/folders/"+testUserID+"/objects/projects/child/large.txt", "large", "writer")
	require.Equal(t, http.StatusRequestEntityTooLarge, response.Code)
	for _, target := range []string{
		"/folders/" + testUserID + "/objects/a/../secret",
		"/folders/" + testUserID + "/objects/.keep",
		"/folders/" + testUserID + "/objects/a%5Cb.txt",
	} {
		response = perform(app, http.MethodPut, target, "x", "writer")
		require.NotEqual(t, http.StatusNoContent, response.Code, target)
	}
}

func TestStrangerCannotListCreateOrShareFolder(t *testing.T) {
	provisioner := &fakeProvisioner{}
	store := &fakeStore{}
	app := testStorageApp(&fakeChecker{}, provisioner, store).routes()
	requests := []struct{ method, target, body string }{
		{http.MethodGet, "/folders/" + testUserID + "?path=", ""},
		{http.MethodPost, "/folders/" + testUserID, `{"parent":"","name":"private"}`},
		{http.MethodGet, "/folders/" + testUserID + "/access?path=", ""},
		{http.MethodPost, "/folders/" + testUserID + "/access/groups/team", `{"path":""}`},
	}
	for _, request := range requests {
		response := perform(app, request.method, request.target, request.body, "stranger")
		require.Equal(t, http.StatusForbidden, response.Code, request.target)
	}
	require.Zero(t, provisioner.serviceTokens)
	require.Empty(t, store.created)
}

func TestCanonicalFolderPaths(t *testing.T) {
	for _, valid := range []string{"", "projects", "projects/Q3 docs", "a/b_c/d.txt"} {
		got, err := canonicalFolderPath(valid)
		require.NoError(t, err, valid)
		require.Equal(t, valid, got)
	}
	for _, invalid := range []string{"/absolute", "a//b", "a/../b", "a/./b", " trailing", "trailing ", "a\\b", ".keep"} {
		_, err := canonicalFolderPath(invalid)
		require.Error(t, err, invalid)
	}
}

func TestStrictJSONRejectsUnknownAndTrailingFields(t *testing.T) {
	app := testStorageApp(&fakeChecker{}, &fakeProvisioner{}, &fakeStore{}).routes()
	for _, body := range []string{
		`{"login":"a","email":"x@y.dev","password":"Strong-Pass1!","invite_token":"forbidden"}`,
		`{"login":"a","email":"x@y.dev","password":"Strong-Pass1!"} {}`,
	} {
		response := perform(app, http.MethodPost, "/register", body, "")
		require.Equal(t, http.StatusBadRequest, response.Code)
	}
}

func TestEnsureWithRetryWaitsForMinIOReadiness(t *testing.T) {
	store := &fakeStore{ensureFailures: 2}
	require.NoError(t, ensureWithRetry(t.Context(), store, time.Millisecond))
	require.Equal(t, 3, store.ensureCalls)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := ensureWithRetry(ctx, &fakeStore{ensureFailures: 1}, time.Hour)
	require.ErrorContains(t, err, "wait for object store")
}

func perform(handler http.Handler, method, target, body, token string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

type fakeChecker struct {
	allowed map[string]bool
	calls   []string
}

func (*fakeChecker) HasRole(context.Context, string, string) (bool, error) { return false, nil }
func (c *fakeChecker) HasRoleWithTag(_ context.Context, _, role, tag string) (bool, error) {
	key := role + "|" + tag
	c.calls = append(c.calls, key)
	return c.allowed[key], nil
}

type fakeProvisioner struct {
	serviceTokens     int
	inviteTokens      []string
	registration      registrationInput
	provisionFailures int
	provisionTokens   []string
	provisionedFolder string
	folderToken       string
	access            folderAccess
	accessFolder      string
	sharedFolder      string
	sharedGroup       string
	sharedToken       string
	shareError        error
}

func (p *fakeProvisioner) IssueServiceToken(context.Context, string, string) (string, error) {
	p.serviceTokens++
	return "service-jwt", nil
}
func (p *fakeProvisioner) CreateInvite(_ context.Context, token, _ string) (string, error) {
	p.inviteTokens = append(p.inviteTokens, token)
	return "invite-token", nil
}
func (p *fakeProvisioner) Register(_ context.Context, input registrationInput) (string, error) {
	p.registration = input
	return testUserID, nil
}
func (p *fakeProvisioner) ProvisionUser(_ context.Context, token, _ string) (string, error) {
	p.provisionTokens = append(p.provisionTokens, token)
	if p.provisionFailures > 0 {
		p.provisionFailures--
		return "", errors.New("temporary provisioning failure")
	}
	return folderRole(testUserID), nil
}
func (p *fakeProvisioner) ProvisionFolder(_ context.Context, token, _ string, folder string) (string, error) {
	p.folderToken = token
	p.provisionedFolder = folder
	return folderRoleForPath(testUserID, folder), nil
}
func (p *fakeProvisioner) ListFolderAccess(_ context.Context, _ string, _ string, folder string) (folderAccess, error) {
	p.accessFolder = folder
	return p.access, nil
}
func (*fakeProvisioner) CreateGroup(context.Context, string, string, string) (string, error) {
	return "storage.group.team", nil
}
func (*fakeProvisioner) AddGroupMember(context.Context, string, string, string, []string) error {
	return nil
}

func (p *fakeProvisioner) ShareFolderWithGroup(_ context.Context, token string, _ string, folder, group string) error {
	p.sharedToken = token
	p.sharedFolder, p.sharedGroup = folder, group
	return p.shareError
}

type fakeStore struct {
	created        []string
	listed         []string
	entries        []storageEntry
	objects        map[string][]byte
	ensureFailures int
	ensureCalls    int
}

func (s *fakeStore) Ensure(context.Context) error {
	s.ensureCalls++
	if s.ensureFailures > 0 {
		s.ensureFailures--
		return errors.New("not ready")
	}
	return nil
}
func (s *fakeStore) CreateFolder(_ context.Context, prefix string) error {
	s.created = append(s.created, prefix)
	return nil
}
func (s *fakeStore) List(_ context.Context, prefix string) ([]storageEntry, error) {
	s.listed = append(s.listed, prefix)
	return append([]storageEntry(nil), s.entries...), nil
}
func (s *fakeStore) Put(_ context.Context, key string, reader io.Reader, size int64, _ string) error {
	data, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	if int64(len(data)) != size {
		return errors.New("size mismatch")
	}
	if s.objects == nil {
		s.objects = make(map[string][]byte)
	}
	s.objects[key] = data
	return nil
}
func (s *fakeStore) Get(_ context.Context, key string) (storedObject, error) {
	data, ok := s.objects[key]
	if !ok {
		return storedObject{}, errObjectNotFound
	}
	return storedObject{Body: io.NopCloser(bytes.NewReader(data)), Size: int64(len(data)), ContentType: "text/plain"}, nil
}
