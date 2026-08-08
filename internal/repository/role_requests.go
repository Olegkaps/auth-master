package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/domain"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type RoleRequest struct {
	ID           uuid.UUID
	RequesterID  uuid.UUID
	TargetUserID uuid.UUID
	RoleID       uuid.UUID
	Status       domain.RoleRequestStatus
	DecidedBy    *uuid.UUID
}

var ErrRoleRequestNotPending = errors.New("role request is not pending")

func (s *Store) CreateRoleRequest(ctx context.Context, requesterID, targetUserID, roleID uuid.UUID) (uuid.UUID, error) {
	row := roleRequestModel{
		RequesterID:  requesterID,
		TargetUserID: targetUserID,
		RoleID:       roleID,
		Status:       "pending",
	}
	if err := s.db.WithContext(ctx).Create(&row).Error; err != nil {
		return uuid.Nil, err
	}
	return row.ID, nil
}

func (s *Store) ListPendingRoleRequests(ctx context.Context, roleID uuid.UUID) ([]RoleRequest, error) {
	var rows []roleRequestModel
	if err := s.db.WithContext(ctx).Where("role_id = ? AND status = ?", roleID, "pending").Find(&rows).Error; err != nil {
		return nil, err
	}
	list := make([]RoleRequest, 0, len(rows))
	for _, r := range rows {
		list = append(list, RoleRequest{
			ID: r.ID, RequesterID: r.RequesterID, TargetUserID: r.TargetUserID,
			RoleID: r.RoleID, Status: domain.RoleRequestStatus(r.Status), DecidedBy: r.DecidedBy,
		})
	}
	return list, nil
}

func (s *Store) DecideRoleRequest(ctx context.Context, id uuid.UUID, approved bool, decidedBy uuid.UUID) error {
	return s.DecideRoleRequestWithMembership(ctx, id, approved, decidedBy, time.Now())
}

// DecideRoleRequestWithMembership changes the request state and, when
// approved, grants membership in the same transaction. Locking the request
// prevents double decisions and eliminates an "approved but not a member" state.
func (s *Store) DecideRoleRequestWithMembership(ctx context.Context, id uuid.UUID, approved bool, decidedBy uuid.UUID, at time.Time) error {
	st := "rejected"
	if approved {
		st = "approved"
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var request roleRequestModel
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", id).Take(&request).Error; err != nil {
			return err
		}
		if request.Status != string(domain.RoleRequestPending) {
			return ErrRoleRequestNotPending
		}
		if approved {
			grantor := decidedBy
			if err := assignUserRoleTx(tx, request.TargetUserID, request.RoleID, domain.RoleMember, &grantor, at, nil, nil); err != nil {
				return err
			}
		}
		res := tx.Model(&roleRequestModel{}).
			Where("id = ? AND status = ?", id, string(domain.RoleRequestPending)).
			Updates(map[string]any{"status": st, "decided_by": decidedBy, "decided_at": at})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return ErrRoleRequestNotPending
		}
		return nil
	})
}

func (s *Store) GetRoleRequest(ctx context.Context, id uuid.UUID) (*RoleRequest, error) {
	var r roleRequestModel
	err := s.db.WithContext(ctx).Where("id = ?", id).Take(&r).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := &RoleRequest{
		ID: r.ID, RequesterID: r.RequesterID, TargetUserID: r.TargetUserID,
		RoleID: r.RoleID, Status: domain.RoleRequestStatus(r.Status), DecidedBy: r.DecidedBy,
	}
	return out, nil
}
