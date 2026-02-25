package organization

import (
	app "github.com/kaitobq/oauth21-oidc-idp/backend/internal/application/organization"
	organizationv1 "github.com/kaitobq/oauth21-oidc-idp/backend/internal/gen/organization/v1"
)

func dtoToProto(d *app.DTO) *organizationv1.Organization {
	return &organizationv1.Organization{
		Id:          d.ID,
		Name:        d.Name,
		DisplayName: d.DisplayName,
		CreatedAt:   d.CreatedAt.Unix(),
		UpdatedAt:   d.UpdatedAt.Unix(),
	}
}
