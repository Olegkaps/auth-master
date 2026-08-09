package main

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/examples/internal/authz"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const supportServiceName = "examples.support.v1.SupportService"

type supportServer struct {
	verifier authz.SubjectVerifier
	checker  authz.Checker
	store    *ticketStore
}

type ticket struct {
	ID      string `json:"id"`
	OwnerID string `json:"owner_id"`
	Body    string `json:"body"`
}
type ticketStore struct {
	mu       sync.RWMutex
	items    map[string]ticket
	fixtures map[string]string
}

func newTicketStore() *ticketStore {
	return &ticketStore{items: make(map[string]ticket), fixtures: make(map[string]string)}
}
func (s *ticketStore) create(owner, body string, fixtureKey ...string) ticket {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := ""
	if len(fixtureKey) > 0 && fixtureKey[0] != "" {
		key = owner + "\x00" + fixtureKey[0]
		if id := s.fixtures[key]; id != "" {
			return s.items[id]
		}
	}
	value := ticket{ID: uuid.NewString(), OwnerID: owner, Body: body}
	s.items[value.ID] = value
	if key != "" {
		s.fixtures[key] = value.ID
	}
	return value
}
func (s *ticketStore) get(id string) (ticket, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.items[id]
	return value, ok
}

func (s *ticketStore) seededTickets() []ticket {
	s.mu.RLock()
	defer s.mu.RUnlock()
	values := make([]ticket, 0, len(s.fixtures))
	for _, id := range s.fixtures {
		values = append(values, s.items[id])
	}
	return values
}

func (s *supportServer) createTicket(ctx context.Context, input *structpb.Struct) (*structpb.Struct, error) {
	token, err := requiredField(input, "access_token", 8192)
	if err != nil {
		return nil, err
	}
	body, err := requiredField(input, "body", 8192)
	if err != nil {
		return nil, err
	}
	subject, err := s.verifiedSubject(ctx, token)
	if err != nil {
		return nil, err
	}
	fixtureKey := input.GetFields()["fixture_key"].GetStringValue()
	if len(fixtureKey) > 64 {
		return nil, status.Error(codes.InvalidArgument, "fixture_key is too long")
	}
	return ticketMessage(s.store.create(subject, body, fixtureKey)), nil
}

func (s *supportServer) getTicket(ctx context.Context, input *structpb.Struct) (*structpb.Struct, error) {
	token, err := requiredToken(input)
	if err != nil {
		return nil, err
	}
	id, err := requiredField(input, "ticket_id", 64)
	if err != nil {
		return nil, err
	}
	subject, err := s.verifiedSubject(ctx, token)
	if err != nil {
		return nil, err
	}
	if _, err := uuid.Parse(id); err != nil {
		return nil, status.Error(codes.InvalidArgument, "ticket_id must be a UUID")
	}
	value, ok := s.store.get(id)
	if !ok {
		return nil, status.Error(codes.NotFound, "ticket not found")
	}
	if subject != value.OwnerID {
		allowed, checkErr := s.anyRole(ctx, token, "support.admin", "support.agent")
		if checkErr != nil {
			return nil, checkErr
		}
		if !allowed {
			return nil, status.Error(codes.PermissionDenied, "ticket access denied")
		}
	}
	return ticketMessage(value), nil
}

func (s *supportServer) verifiedSubject(ctx context.Context, token string) (string, error) {
	subject, err := s.verifier.VerifySubject(ctx, token)
	if err != nil {
		return "", verificationError(err)
	}
	if subject == "" {
		return "", invalidAccessToken()
	}
	return subject, nil
}

func verificationError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), status.Code(err) == codes.Canceled:
		return status.Error(codes.Canceled, "authentication canceled")
	case errors.Is(err, context.DeadlineExceeded), status.Code(err) == codes.DeadlineExceeded:
		return status.Error(codes.DeadlineExceeded, "authentication deadline exceeded")
	case status.Code(err) == codes.Unauthenticated:
		return invalidAccessToken()
	default:
		return status.Error(codes.Unavailable, "authentication service unavailable")
	}
}

func invalidAccessToken() error {
	return status.Error(codes.Unauthenticated, "invalid access token")
}

func requiredToken(input *structpb.Struct) (string, error) {
	value := input.GetFields()["access_token"].GetStringValue()
	if value == "" {
		return "", status.Error(codes.Unauthenticated, "access_token is required")
	}
	if len(value) > 8192 {
		return "", status.Error(codes.Unauthenticated, "access_token is too long")
	}
	return value, nil
}

func (s *supportServer) anyRole(ctx context.Context, token string, roles ...string) (bool, error) {
	for _, role := range roles {
		allowed, err := s.checker.HasRole(ctx, token, role)
		if err != nil {
			return false, err
		}
		if allowed {
			return true, nil
		}
	}
	return false, nil
}

func requiredField(input *structpb.Struct, name string, max int) (string, error) {
	value := input.GetFields()[name].GetStringValue()
	if value == "" {
		return "", status.Errorf(codes.InvalidArgument, "%s is required", name)
	}
	if len(value) > max {
		return "", status.Errorf(codes.InvalidArgument, "%s is too long", name)
	}
	return value, nil
}

func ticketMessage(value ticket) *structpb.Struct {
	message, err := structpb.NewStruct(map[string]any{"id": value.ID, "owner_id": value.OwnerID, "body": value.Body})
	if err != nil {
		panic(fmt.Sprintf("build ticket response: %v", err))
	}
	return message
}

func registerSupportService(server grpc.ServiceRegistrar, implementation *supportServer) {
	server.RegisterService(&grpc.ServiceDesc{ServiceName: supportServiceName, HandlerType: (*supportService)(nil), Methods: []grpc.MethodDesc{
		{MethodName: "CreateTicket", Handler: unaryHandler(implementation.createTicket)},
		{MethodName: "GetTicket", Handler: unaryHandler(implementation.getTicket)},
	}}, implementation)
}

type supportService interface{}
type supportMethod func(context.Context, *structpb.Struct) (*structpb.Struct, error)

func unaryHandler(method supportMethod) grpc.MethodHandler {
	return func(_ any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
		input := new(structpb.Struct)
		if err := decode(input); err != nil {
			return nil, err
		}
		if interceptor == nil {
			return method(ctx, input)
		}
		info := &grpc.UnaryServerInfo{FullMethod: supportServiceName}
		return interceptor(ctx, input, info, func(callCtx context.Context, request any) (any, error) {
			return method(callCtx, request.(*structpb.Struct))
		})
	}
}
