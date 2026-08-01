package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/domain"
	"gorm.io/gorm"
)

type RoleRequest struct {
	ID           uuid.UUID
	RequesterID  uuid.UUID
	TargetUserID uuid.UUID
	RoleID       uuid.UUID
	Status       domain.RoleRequestStatus
	DecidedBy    *uuid.UUID
}

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
	st := "rejected"
	if approved {
		st = "approved"
	}
	res := s.db.WithContext(ctx).Model(&roleRequestModel{}).
		Where("id = ? AND status = ?", id, "pending").
		Updates(map[string]any{
			"status":     st,
			"decided_by": decidedBy,
			"decided_at": time.Now(),
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return errors.New("request not pending")
	}
	return nil
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
