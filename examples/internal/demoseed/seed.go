package demoseed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	authv1 "github.com/olegkapshai/auth-master/api/auth/v1"
	"github.com/olegkapshai/auth-master/examples/internal/demoauth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

const DemoPassword = "Example!Passw0rd9"

type Persona struct {
	Key          string
	Login        string
	Email        string
	Capabilities string
}

func (p Persona) Credentials() demoauth.Credentials {
	return demoauth.Credentials{Login: p.Login, Email: p.Email, Password: DemoPassword}
}

type RoleGrant struct {
	RoleName   string
	PersonaKey string
	Level      authv1.RoleLevel
	Tags       []string
}

type Plan struct {
	Example  string
	Personas []Persona
	Grants   []RoleGrant
}

func PlanFor(example string) (Plan, error) {
	personas := func(values ...Persona) []Persona { return values }
	switch example {
	case "deployment-api":
		return Plan{Example: example, Personas: personas(
			persona("global", "deploy-global", "deploy-global@example.test", "deploy and delete every application"),
			persona("developer", "deploy-developer", "deploy-developer@example.test", "deploy any application; delete denied"),
			persona("billing", "deploy-billing", "deploy-billing@example.test", "deploy/delete billing only"),
			persona("stranger", "deploy-stranger", "deploy-stranger@example.test", "all deployment actions denied"),
		), Grants: []RoleGrant{
			{RoleName: "deploy.global-admin", PersonaKey: "global", Level: authv1.RoleLevel_ROLE_LEVEL_MEMBER},
			{RoleName: "deploy.developer", PersonaKey: "developer", Level: authv1.RoleLevel_ROLE_LEVEL_MEMBER},
			{RoleName: "deploy.app.billing.admin", PersonaKey: "billing", Level: authv1.RoleLevel_ROLE_LEVEL_ROLE_ADMIN},
		}}, nil
	case "support-desk":
		return Plan{Example: example, Personas: personas(
			persona("owner", "support-owner", "support-owner@example.test", "create and read own tickets"),
			persona("agent", "support-agent", "support-agent@example.test", "read every ticket"),
			persona("admin", "support-admin", "support-admin@example.test", "read every ticket as support administrator"),
			persona("stranger", "support-stranger", "support-stranger@example.test", "other users' tickets denied"),
		), Grants: []RoleGrant{
			{RoleName: "support.agent", PersonaKey: "agent", Level: authv1.RoleLevel_ROLE_LEVEL_MEMBER},
			{RoleName: "support.admin", PersonaKey: "admin", Level: authv1.RoleLevel_ROLE_LEVEL_MEMBER},
		}}, nil
	case "minio-storage":
		return Plan{Example: example, Personas: personas(
			persona("owner", "storage-owner", "storage-owner@example.test", "administer own folder and sharing"),
			persona("reader", "storage-reader", "storage-reader@example.test", "read the shared demo folder"),
			persona("writer", "storage-writer", "storage-writer@example.test", "write to the shared demo folder"),
			persona("admin", "storage-admin", "storage-admin@example.test", "read, write, and administer the shared folder"),
			persona("stranger", "storage-stranger", "storage-stranger@example.test", "shared folder denied"),
		)}, nil
	default:
		return Plan{}, fmt.Errorf("unsupported example %q", example)
	}
}

func persona(key, login, email, capabilities string) Persona {
	return Persona{Key: key, Login: login, Email: email, Capabilities: capabilities}
}

func (p Plan) Persona(key string) (Persona, bool) {
	for _, candidate := range p.Personas {
		if candidate.Key == key || candidate.Login == key {
			return candidate, true
		}
	}
	return Persona{}, false
}

type Config struct {
	Example       string
	AuthHTTPURL   string
	AuthGRPCAddr  string
	MailpitURL    string
	AppURL        string
	ServiceLogin  string
	ServiceSecret string
	HTTPClient    *http.Client
}

type Seeder struct {
	config Config
	plan   Plan
	auth   demoauth.Client
	conn   *grpc.ClientConn
	admin  authv1.AdminServiceClient
	roles  authv1.RoleServiceClient
	public authv1.AuthServiceClient
	users  map[string]string
}

type Result struct {
	Users map[string]string
}

func Run(ctx context.Context, config Config) (Result, error) {
	plan, err := PlanFor(config.Example)
	if err != nil {
		return Result{}, err
	}
	auth := demoauth.Client{HTTP: config.HTTPClient, AuthURL: config.AuthHTTPURL, MailURL: config.MailpitURL}
	connection, err := grpc.NewClient(config.AuthGRPCAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return Result{}, fmt.Errorf("connect to auth gRPC: %w", err)
	}
	defer connection.Close()
	seeder := &Seeder{
		config: config, plan: plan, auth: auth, conn: connection,
		admin: authv1.NewAdminServiceClient(connection), roles: authv1.NewRoleServiceClient(connection),
		public: authv1.NewAuthServiceClient(connection), users: make(map[string]string),
	}
	if err := seeder.reconcileIdentities(ctx); err != nil {
		return Result{}, err
	}
	if err := seeder.reconcileRoles(ctx); err != nil {
		return Result{}, err
	}
	switch config.Example {
	case "support-desk":
		err = seeder.seedSupport(ctx)
	case "minio-storage":
		err = seeder.seedStorage(ctx)
	}
	if err != nil {
		return Result{}, err
	}
	return Result{Users: seeder.users}, nil
}

func (s *Seeder) reconcileIdentities(ctx context.Context) error {
	for _, persona := range s.plan.Personas {
		id, err := s.findUser(ctx, persona.Login)
		if status.Code(err) == codes.NotFound {
			if s.config.Example == "minio-storage" {
				var registration struct {
					UserID             string `json:"user_id"`
					Retry              string `json:"retry"`
					ProvisioningStatus string `json:"provisioning_status"`
				}
				if registerErr := s.appJSON(ctx, http.MethodPost, "/register", map[string]string{
					"login": persona.Login, "email": persona.Email, "password": DemoPassword,
				}, &registration, http.StatusCreated, http.StatusAccepted); registerErr != nil {
					return fmt.Errorf("register and provision %s: %w", persona.Login, registerErr)
				}
				if registration.UserID == "" {
					return fmt.Errorf("register %s returned no user_id", persona.Login)
				}
				if registration.ProvisioningStatus == "pending" && registration.Retry != "" {
					if retryErr := s.appJSON(ctx, http.MethodPost, registration.Retry, nil, nil, http.StatusOK); retryErr != nil {
						return fmt.Errorf("retry provisioning %s: %w", persona.Login, retryErr)
					}
				}
				id = registration.UserID
				s.users[persona.Key] = id
				continue
			}
			callCtx, cancel, tokenErr := s.serviceContext(ctx)
			if tokenErr != nil {
				return fmt.Errorf("authorize invite for %s: %w", persona.Login, tokenErr)
			}
			invite, inviteErr := s.admin.CreateRegistrationInvite(callCtx, &authv1.CreateRegistrationInviteRequest{
				Email: &persona.Email, Ttl: durationpb.New(time.Hour),
			})
			cancel()
			if inviteErr != nil {
				return fmt.Errorf("invite %s: %w", persona.Login, inviteErr)
			}
			registered, registerErr := s.public.Register(ctx, &authv1.RegisterRequest{
				InviteToken: invite.GetToken(), Login: persona.Login, Email: persona.Email, Password: DemoPassword,
			})
			if registerErr != nil {
				return fmt.Errorf("register %s: %w", persona.Login, registerErr)
			}
			id = registered.GetUserId()
		} else if err != nil {
			return fmt.Errorf("find user %s: %w", persona.Login, err)
		}
		s.users[persona.Key] = id
	}
	return nil
}

func (s *Seeder) findUser(ctx context.Context, login string) (string, error) {
	callCtx, cancel, err := s.serviceContext(ctx)
	if err != nil {
		return "", err
	}
	defer cancel()
	response, err := s.admin.ListUsers(callCtx, &authv1.ListUsersRequest{Page: &authv1.PageRequest{Query: login, PageSize: 100}})
	if err != nil {
		return "", err
	}
	for _, user := range response.GetUsers() {
		if strings.EqualFold(user.GetLogin(), login) {
			if user.GetKind() != authv1.UserKind_USER_KIND_HUMAN {
				return "", status.Errorf(codes.FailedPrecondition, "%s exists but is not a human user", login)
			}
			return user.GetId(), nil
		}
	}
	return "", status.Error(codes.NotFound, "user not found")
}

func (s *Seeder) reconcileRoles(ctx context.Context) error {
	for _, grant := range s.plan.Grants {
		roleID, err := s.ensureRole(ctx, grant.RoleName)
		if err != nil {
			return err
		}
		for _, tag := range grant.Tags {
			callCtx, cancel, tokenErr := s.serviceContext(ctx)
			if tokenErr != nil {
				return tokenErr
			}
			_, tagErr := s.roles.AddRoleTag(callCtx, &authv1.AddRoleTagRequest{RoleId: roleID, Tag: tag})
			cancel()
			if tagErr != nil && status.Code(tagErr) != codes.AlreadyExists {
				return fmt.Errorf("add tag %s to %s: %w", tag, grant.RoleName, tagErr)
			}
		}
		callCtx, cancel, tokenErr := s.serviceContext(ctx)
		if tokenErr != nil {
			return tokenErr
		}
		_, err = s.roles.AssignRole(callCtx, &authv1.AssignRoleRequest{
			RoleId: roleID, UserId: s.users[grant.PersonaKey], Level: grant.Level, TagGrants: grant.Tags,
		})
		cancel()
		if err != nil {
			return fmt.Errorf("assign %s to %s: %w", grant.PersonaKey, grant.RoleName, err)
		}
	}
	return nil
}

func (s *Seeder) ensureRole(ctx context.Context, name string) (string, error) {
	callCtx, cancel, tokenErr := s.serviceContext(ctx)
	if tokenErr != nil {
		return "", tokenErr
	}
	response, err := s.roles.ListRoles(callCtx, &authv1.ListRolesRequest{Page: &authv1.PageRequest{Query: name, PageSize: 100}})
	cancel()
	if err != nil {
		return "", err
	}
	for _, role := range response.GetRoles() {
		if strings.EqualFold(role.GetName(), name) {
			return role.GetId(), nil
		}
	}
	callCtx, cancel, tokenErr = s.serviceContext(ctx)
	if tokenErr != nil {
		return "", tokenErr
	}
	created, err := s.roles.CreateRole(callCtx, &authv1.CreateRoleRequest{Name: name, Description: "Seeded example role " + name})
	cancel()
	if err == nil {
		return created.GetRoleId(), nil
	}
	if status.Code(err) != codes.AlreadyExists {
		return "", fmt.Errorf("create role %s: %w", name, err)
	}
	callCtx, cancel, tokenErr = s.serviceContext(ctx)
	if tokenErr != nil {
		return "", tokenErr
	}
	response, findErr := s.roles.ListRoles(callCtx, &authv1.ListRolesRequest{Page: &authv1.PageRequest{Query: name, PageSize: 100}})
	cancel()
	if findErr != nil {
		return "", findErr
	}
	for _, role := range response.GetRoles() {
		if strings.EqualFold(role.GetName(), name) {
			return role.GetId(), nil
		}
	}
	return "", fmt.Errorf("role %s exists but could not be resolved", name)
}

func (s *Seeder) seedSupport(ctx context.Context) error {
	owner, _ := s.plan.Persona("owner")
	ownerToken, err := s.auth.HumanToken(ctx, owner.Credentials())
	if err != nil {
		return fmt.Errorf("login support owner: %w", err)
	}
	return s.appJSON(ctx, http.MethodPost, "/rpc", map[string]string{
		"Method": "CreateTicket", "AccessToken": ownerToken,
		"Body": "Seeded ticket: customer cannot access billing", "FixtureKey": "welcome",
	}, nil, http.StatusOK)
}

func (s *Seeder) seedStorage(ctx context.Context) error {
	ownerID := s.users["owner"]
	serviceToken, err := s.freshServiceToken(ctx)
	if err != nil {
		return fmt.Errorf("authorize storage group creation: %w", err)
	}
	groupErr := s.appJSONWithToken(ctx, http.MethodPost, "/groups", map[string]string{
		"name": "demo-team", "manager_user_id": ownerID,
	}, serviceToken, nil, http.StatusCreated, http.StatusConflict)
	serviceToken = ""
	if groupErr != nil {
		return fmt.Errorf("create storage group: %w", groupErr)
	}
	serviceToken, err = s.freshServiceToken(ctx)
	if err != nil {
		return fmt.Errorf("authorize storage project group creation: %w", err)
	}
	groupErr = s.appJSONWithToken(ctx, http.MethodPost, "/groups", map[string]string{
		"name": "project-reviewers", "manager_user_id": ownerID,
	}, serviceToken, nil, http.StatusCreated, http.StatusConflict)
	serviceToken = ""
	if groupErr != nil {
		return fmt.Errorf("create storage project group: %w", groupErr)
	}
	owner, _ := s.plan.Persona("owner")
	ownerToken, err := s.auth.HumanToken(ctx, owner.Credentials())
	if err != nil {
		return fmt.Errorf("login storage owner: %w", err)
	}
	if err := s.appJSONWithToken(ctx, http.MethodPost, "/folders/"+ownerID, map[string]string{
		"parent": "", "name": "welcome",
	}, ownerToken, nil, http.StatusCreated); err != nil {
		return fmt.Errorf("create storage welcome folder: %w", err)
	}
	if err := s.appJSONWithToken(ctx, http.MethodPost, "/folders/"+ownerID, map[string]string{
		"parent": "welcome", "name": "projects",
	}, ownerToken, nil, http.StatusCreated); err != nil {
		return fmt.Errorf("create storage projects folder: %w", err)
	}
	if err := s.appJSONWithToken(ctx, http.MethodPost, "/folders/"+ownerID, map[string]string{
		"parent": "", "name": "private",
	}, ownerToken, nil, http.StatusCreated); err != nil {
		return fmt.Errorf("create storage private sibling: %w", err)
	}
	for key, tags := range map[string][]string{
		"reader": {"read"}, "writer": {"read", "write"}, "admin": {"read", "write", "admin"},
	} {
		if err := s.appJSONWithToken(ctx, http.MethodPost, "/groups/demo-team/members", map[string]any{
			"user_id": s.users[key], "tags": tags,
		}, ownerToken, nil, http.StatusNoContent); err != nil {
			return fmt.Errorf("add storage %s: %w", key, err)
		}
	}
	if err := s.appJSONWithToken(ctx, http.MethodPost, "/groups/project-reviewers/members", map[string]any{
		"user_id": s.users["stranger"], "tags": []string{"read"},
	}, ownerToken, nil, http.StatusNoContent); err != nil {
		return fmt.Errorf("add storage project reviewer: %w", err)
	}
	if err := s.appJSONWithToken(ctx, http.MethodPost, "/folders/"+ownerID+"/access/groups/demo-team", map[string]string{"path": "welcome"}, ownerToken, nil, http.StatusNoContent, http.StatusConflict); err != nil {
		return fmt.Errorf("share storage folder: %w", err)
	}
	objectPath := "/folders/" + ownerID + "/objects/welcome/readme.txt"
	statusCode, err := s.appRequest(ctx, http.MethodGet, objectPath, nil, ownerToken, nil)
	if err != nil {
		return err
	}
	if statusCode == http.StatusNotFound {
		statusCode, err = s.appRequest(ctx, http.MethodPut, objectPath, []byte("Welcome to the seeded shared folder.\n"), ownerToken, map[string]string{"Content-Type": "text/plain"})
	}
	if err != nil || statusCode != http.StatusOK && statusCode != http.StatusNoContent {
		return fmt.Errorf("seed storage welcome object returned %d: %w", statusCode, err)
	}
	nestedPath := "/folders/" + ownerID + "/objects/welcome/projects/roadmap.txt"
	statusCode, err = s.appRequest(ctx, http.MethodGet, nestedPath, nil, ownerToken, nil)
	if err != nil {
		return err
	}
	if statusCode == http.StatusNotFound {
		statusCode, err = s.appRequest(ctx, http.MethodPut, nestedPath, []byte("Seeded project roadmap.\n"), ownerToken, map[string]string{"Content-Type": "text/plain"})
	}
	if err != nil || statusCode != http.StatusOK && statusCode != http.StatusNoContent {
		return fmt.Errorf("seed storage roadmap object returned %d: %w", statusCode, err)
	}
	return nil
}

func (s *Seeder) freshServiceToken(ctx context.Context) (string, error) {
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.auth.ServiceToken(callCtx, s.config.ServiceLogin, s.config.ServiceSecret)
}

func (s *Seeder) serviceContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	token, err := s.freshServiceToken(ctx)
	if err != nil {
		return nil, func() {}, err
	}
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	return metadata.AppendToOutgoingContext(callCtx, "authorization", "Bearer "+token), cancel, nil
}

func (s *Seeder) appJSON(ctx context.Context, method, path string, input, output any, expected ...int) error {
	return s.appJSONWithToken(ctx, method, path, input, "", output, expected...)
}

func (s *Seeder) appJSONWithToken(ctx context.Context, method, path string, input any, token string, output any, expected ...int) error {
	var body []byte
	var err error
	if input != nil {
		body, err = json.Marshal(input)
		if err != nil {
			return err
		}
	}
	code, content, err := s.appRequestContent(ctx, method, path, body, token, map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return err
	}
	for _, candidate := range expected {
		if code == candidate {
			if output != nil && len(bytes.TrimSpace(content)) > 0 {
				return json.Unmarshal(content, output)
			}
			return nil
		}
	}
	return fmt.Errorf("%s %s returned %d: %s", method, path, code, strings.TrimSpace(string(content)))
}

func (s *Seeder) appRequest(ctx context.Context, method, path string, body []byte, token string, headers map[string]string) (int, error) {
	code, content, err := s.appRequestContent(ctx, method, path, body, token, headers)
	if err != nil {
		return 0, err
	}
	if code >= 500 {
		return code, fmt.Errorf("%s %s returned %d: %s", method, path, code, strings.TrimSpace(string(content)))
	}
	return code, nil
}

func (s *Seeder) appRequestContent(ctx context.Context, method, path string, body []byte, token string, headers map[string]string) (int, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(s.config.AppURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	client := s.config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	} else {
		copy := *client
		client = &copy
		if client.Timeout == 0 {
			client.Timeout = 10 * time.Second
		}
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	return response.StatusCode, content, err
}
