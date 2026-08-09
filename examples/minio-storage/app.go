package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/examples/internal/authz"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const maxRelativePathBytes = 1024

var safePathSegment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$`)

type serviceCredentials struct {
	login  string
	secret string
}

type storageApp struct {
	checker        authz.Checker
	provisioner    authProvisioner
	objects        objectStore
	service        serviceCredentials
	maxUploadBytes int64
	pending        *pendingRegistrations
}

type pendingRegistrations struct {
	mu      sync.Mutex
	userIDs map[string]struct{}
}

func newPendingRegistrations() *pendingRegistrations {
	return &pendingRegistrations{userIDs: make(map[string]struct{})}
}

func (p *pendingRegistrations) add(userID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.userIDs[userID] = struct{}{}
}

func (p *pendingRegistrations) has(userID string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.userIDs[userID]
	return ok
}

func (p *pendingRegistrations) remove(userID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.userIDs, userID)
}

func (a storageApp) routes() http.Handler {
	if a.pending == nil {
		a.pending = newPendingRegistrations()
	}
	router := chi.NewRouter()
	router.Get("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(storagePage))
	})
	router.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	router.Post("/register", a.register)
	router.Post("/registrations/{userID}/provision", a.reconcileRegistration)
	router.Post("/groups", a.createGroup)
	router.Post("/groups/{group}/members", a.addGroupMember)
	router.Get("/folders/{ownerID}", a.listFolder)
	router.Post("/folders/{ownerID}", a.createFolder)
	router.Get("/folders/{ownerID}/access", a.listFolderAccess)
	router.Post("/folders/{ownerID}/access/groups/{group}", a.shareFolder)
	router.Get("/folders/{ownerID}/objects/*", a.getObject)
	router.Put("/folders/{ownerID}/objects/*", a.putObject)
	return router
}

func (a storageApp) register(w http.ResponseWriter, r *http.Request) {
	var body registrationInput
	if !decodeJSON(w, r, &body) {
		return
	}
	body.Login = strings.TrimSpace(body.Login)
	body.Email = strings.TrimSpace(body.Email)
	if body.Login == "" || body.Email == "" || body.Password == "" {
		writeError(w, http.StatusBadRequest, errors.New("login, email, and password are required"))
		return
	}
	serviceToken, err := a.serviceToken(r.Context())
	if err != nil {
		writeProvisioningError(w, err)
		return
	}
	invite, err := a.provisioner.CreateInvite(r.Context(), serviceToken, body.Email)
	if err != nil {
		writeRPCError(w, err)
		return
	}
	body.InviteToken = invite
	userID, err := a.provisioner.Register(r.Context(), body)
	if err != nil {
		writeRPCError(w, err)
		return
	}
	if err := a.provision(r.Context(), serviceToken, userID); err != nil {
		a.pending.add(userID)
		writeJSON(w, http.StatusAccepted, registrationResponse(userID, "pending"))
		return
	}
	writeJSON(w, http.StatusCreated, registrationResponse(userID, "ready"))
}

func registrationResponse(userID, state string) map[string]string {
	return map[string]string{
		"user_id": userID, "folder": userID, "role": folderRole(userID),
		"provisioning_status": state,
		"retry":               "/registrations/" + userID + "/provision",
	}
}

func (a storageApp) reconcileRegistration(w http.ResponseWriter, r *http.Request) {
	userID, ok := canonicalOwnerID(w, chi.URLParam(r, "userID"))
	if !ok {
		return
	}
	if !a.pending.has(userID) {
		writeError(w, http.StatusNotFound, errors.New("pending registration not found"))
		return
	}
	serviceToken, err := a.serviceToken(r.Context())
	if err != nil {
		writeProvisioningError(w, err)
		return
	}
	if err := a.provision(r.Context(), serviceToken, userID); err != nil {
		writeRPCError(w, err)
		return
	}
	a.pending.remove(userID)
	writeJSON(w, http.StatusOK, registrationResponse(userID, "ready"))
}

func (a storageApp) provision(ctx context.Context, serviceToken, userID string) error {
	if _, err := a.provisioner.ProvisionUser(ctx, serviceToken, userID); err != nil {
		return err
	}
	if err := a.objects.CreateFolder(ctx, userID); err != nil {
		return fmt.Errorf("create MinIO prefix: %w", err)
	}
	return nil
}

func (a storageApp) createGroup(w http.ResponseWriter, r *http.Request) {
	actorToken, ok := requestToken(w, r)
	if !ok {
		return
	}
	var body struct {
		Name          string `json:"name"`
		ManagerUserID string `json:"manager_user_id"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if _, err := uuid.Parse(body.ManagerUserID); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid manager_user_id"))
		return
	}
	role, err := a.provisioner.CreateGroup(r.Context(), actorToken, body.Name, body.ManagerUserID)
	if err != nil {
		writeRPCError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"role": role})
}

func (a storageApp) addGroupMember(w http.ResponseWriter, r *http.Request) {
	actorToken, ok := requestToken(w, r)
	if !ok {
		return
	}
	var body struct {
		UserID string   `json:"user_id"`
		Tags   []string `json:"tags"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if _, err := uuid.Parse(body.UserID); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid user_id"))
		return
	}
	if err := a.provisioner.AddGroupMember(r.Context(), actorToken, chi.URLParam(r, "group"), body.UserID, body.Tags); err != nil {
		writeRPCError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a storageApp) listFolder(w http.ResponseWriter, r *http.Request) {
	ownerID, ok := canonicalOwnerID(w, chi.URLParam(r, "ownerID"))
	if !ok {
		return
	}
	folder, err := canonicalFolderPath(r.URL.Query().Get("path"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !a.authorizeFolder(w, r, ownerID, folder, "read") {
		return
	}
	entries, err := a.objects.List(r.Context(), objectPrefix(ownerID, folder))
	if err != nil {
		writeError(w, http.StatusBadGateway, errors.New("object store unavailable"))
		return
	}
	for i := range entries {
		entries[i].Path = joinFolder(folder, entries[i].Name)
	}
	writeJSON(w, http.StatusOK, map[string]any{"path": folder, "entries": entries})
}

func (a storageApp) createFolder(w http.ResponseWriter, r *http.Request) {
	ownerID, ok := canonicalOwnerID(w, chi.URLParam(r, "ownerID"))
	if !ok {
		return
	}
	var body struct {
		Parent string `json:"parent"`
		Name   string `json:"name"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	parent, err := canonicalFolderPath(body.Parent)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	name, err := canonicalSegment(body.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !a.authorizeFolder(w, r, ownerID, parent, "admin") {
		return
	}
	folder := joinFolder(parent, name)
	serviceToken, err := a.serviceToken(r.Context())
	if err != nil {
		writeProvisioningError(w, err)
		return
	}
	if _, err := a.provisioner.ProvisionFolder(r.Context(), serviceToken, ownerID, folder); err != nil {
		writeRPCError(w, err)
		return
	}
	if err := a.objects.CreateFolder(r.Context(), objectPrefix(ownerID, folder)); err != nil {
		writeError(w, http.StatusBadGateway, errors.New("object store unavailable"))
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"path": folder, "role": folderRoleForPath(ownerID, folder)})
}

func (a storageApp) listFolderAccess(w http.ResponseWriter, r *http.Request) {
	ownerID, ok := canonicalOwnerID(w, chi.URLParam(r, "ownerID"))
	if !ok {
		return
	}
	folder, err := canonicalFolderPath(r.URL.Query().Get("path"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !a.authorizeFolder(w, r, ownerID, folder, "admin") {
		return
	}
	serviceToken, err := a.serviceToken(r.Context())
	if err != nil {
		writeProvisioningError(w, err)
		return
	}
	access, err := a.provisioner.ListFolderAccess(r.Context(), serviceToken, ownerID, folder)
	if err != nil {
		writeRPCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, access)
}

func (a storageApp) shareFolder(w http.ResponseWriter, r *http.Request) {
	actorToken, tokenOK := requestToken(w, r)
	if !tokenOK {
		return
	}
	ownerID, ok := canonicalOwnerID(w, chi.URLParam(r, "ownerID"))
	if !ok {
		return
	}
	var body struct {
		Path string `json:"path"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	folder, err := canonicalFolderPath(body.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !a.authorizeFolder(w, r, ownerID, folder, "admin") {
		return
	}
	// Mounting requires authority over both the selected folder and the group.
	// Forward the human actor so auth-master enforces that invariant; the
	// provisioning service must never act as a confused deputy for sharing.
	if err := a.provisioner.ShareFolderWithGroup(r.Context(), actorToken, ownerID, folder, chi.URLParam(r, "group")); err != nil {
		writeRPCError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a storageApp) getObject(w http.ResponseWriter, r *http.Request) {
	ownerID, key, ok := objectPath(w, r)
	if !ok || !a.authorizeFolder(w, r, ownerID, parentFolder(key), "read") {
		return
	}
	object, err := a.objects.Get(r.Context(), ownerID+"/"+key)
	if err != nil {
		if errors.Is(err, errObjectNotFound) {
			writeError(w, http.StatusNotFound, err)
		} else {
			writeError(w, http.StatusBadGateway, errors.New("object store unavailable"))
		}
		return
	}
	defer object.Body.Close()
	if object.ContentType != "" {
		w.Header().Set("Content-Type", object.ContentType)
	}
	w.Header().Set("Content-Length", fmt.Sprint(object.Size))
	_, _ = io.Copy(w, object.Body)
}

func (a storageApp) putObject(w http.ResponseWriter, r *http.Request) {
	ownerID, key, ok := objectPath(w, r)
	if !ok || !a.authorizeFolder(w, r, ownerID, parentFolder(key), "write") {
		return
	}
	if r.ContentLength < 0 {
		writeError(w, http.StatusLengthRequired, errors.New("Content-Length is required"))
		return
	}
	limit := a.maxUploadBytes
	if limit <= 0 {
		limit = 16 << 20
	}
	if r.ContentLength > limit {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Errorf("upload exceeds %d bytes", limit))
		return
	}
	if err := a.objects.Put(r.Context(), ownerID+"/"+key, r.Body, r.ContentLength, r.Header.Get("Content-Type")); err != nil {
		writeError(w, http.StatusBadGateway, errors.New("object store unavailable"))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a storageApp) authorizeFolder(w http.ResponseWriter, r *http.Request, ownerID, folder, tag string) bool {
	token, err := authz.BearerToken(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return false
	}
	role := folderRoleForPath(ownerID, folder)
	allowed, err := a.checker.HasRoleWithTag(r.Context(), token, role, tag)
	if err == nil && !allowed && tag != "admin" {
		allowed, err = a.checker.HasRoleWithTag(r.Context(), token, role, "admin")
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, errors.New("authorization service unavailable"))
		return false
	}
	if !allowed {
		writeError(w, http.StatusForbidden, errors.New("folder permission denied"))
		return false
	}
	return true
}

func (a storageApp) serviceToken(ctx context.Context) (string, error) {
	if strings.TrimSpace(a.service.login) == "" || a.service.secret == "" {
		return "", errors.New("storage provisioning service is not configured")
	}
	return a.provisioner.IssueServiceToken(ctx, a.service.login, a.service.secret)
}

func canonicalOwnerID(w http.ResponseWriter, raw string) (string, bool) {
	id, err := uuid.Parse(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid ownerID"))
		return "", false
	}
	return strings.ToLower(id.String()), true
}

func objectPath(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	ownerID, ok := canonicalOwnerID(w, chi.URLParam(r, "ownerID"))
	if !ok {
		return "", "", false
	}
	raw := strings.TrimPrefix(chi.URLParam(r, "*"), "/")
	clean, err := canonicalObjectPath(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return "", "", false
	}
	return ownerID, clean, true
}

func canonicalFolderPath(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	return canonicalPath(raw, true)
}

func canonicalObjectPath(raw string) (string, error) {
	return canonicalPath(raw, false)
}

func canonicalPath(raw string, folder bool) (string, error) {
	if raw == "" || len(raw) > maxRelativePathBytes || strings.Contains(raw, "\\") || path.IsAbs(raw) || path.Clean(raw) != raw {
		return "", errors.New("invalid relative path")
	}
	segments := strings.Split(raw, "/")
	for _, segment := range segments {
		if _, err := canonicalSegment(segment); err != nil {
			return "", err
		}
	}
	if !folder && len(segments) == 0 {
		return "", errors.New("object path is required")
	}
	return strings.Join(segments, "/"), nil
}

func canonicalSegment(raw string) (string, error) {
	if raw != strings.TrimSpace(raw) || raw == "." || raw == ".." || !safePathSegment.MatchString(raw) {
		return "", errors.New("path segments must be 1-128 safe characters")
	}
	return raw, nil
}

func parentFolder(relative string) string {
	if index := strings.LastIndex(relative, "/"); index >= 0 {
		return relative[:index]
	}
	return ""
}

func joinFolder(parent, name string) string {
	if parent == "" {
		return name
	}
	return parent + "/" + name
}

func objectPrefix(ownerID, folder string) string {
	if folder == "" {
		return ownerID
	}
	return ownerID + "/" + folder
}

func decodeJSON(w http.ResponseWriter, r *http.Request, output any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid JSON"))
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		writeError(w, http.StatusBadRequest, errors.New("invalid JSON"))
		return false
	}
	return true
}

func requestToken(w http.ResponseWriter, r *http.Request) (string, bool) {
	token, err := authz.BearerToken(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return "", false
	}
	return token, true
}

func writeJSON(w http.ResponseWriter, statusCode int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, statusCode int, err error) {
	writeJSON(w, statusCode, map[string]string{"error": err.Error()})
}

func writeProvisioningError(w http.ResponseWriter, _ error) {
	writeError(w, http.StatusServiceUnavailable, errors.New("storage provisioning service unavailable"))
}

func writeRPCError(w http.ResponseWriter, err error) {
	code := status.Code(err)
	httpStatus := http.StatusBadGateway
	switch code {
	case codes.InvalidArgument:
		httpStatus = http.StatusBadRequest
	case codes.Unauthenticated:
		httpStatus = http.StatusUnauthorized
	case codes.PermissionDenied:
		httpStatus = http.StatusForbidden
	case codes.NotFound:
		httpStatus = http.StatusNotFound
	case codes.AlreadyExists, codes.FailedPrecondition, codes.Aborted:
		httpStatus = http.StatusConflict
	case codes.DeadlineExceeded:
		httpStatus = http.StatusGatewayTimeout
	case codes.Unavailable:
		httpStatus = http.StatusServiceUnavailable
	}
	writeError(w, httpStatus, err)
}
