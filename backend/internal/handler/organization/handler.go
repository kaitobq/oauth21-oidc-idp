package organization

import (
	"context"

	"connectrpc.com/connect"

	app "github.com/kaitobq/oauth21-oidc-idp/backend/internal/application/organization"
	organizationv1 "github.com/kaitobq/oauth21-oidc-idp/backend/internal/gen/organization/v1"
	"github.com/kaitobq/oauth21-oidc-idp/backend/internal/gen/organization/v1/organizationv1connect"
)

// Handler implements the OrganizationService Connect RPC service.
type Handler struct {
	facade *app.Facade
}

var _ organizationv1connect.OrganizationServiceHandler = (*Handler)(nil)

// NewHandler creates a new Organization handler.
func NewHandler(facade *app.Facade) *Handler {
	return &Handler{facade: facade}
}

func (h *Handler) CreateOrganization(
	ctx context.Context,
	req *connect.Request[organizationv1.CreateOrganizationRequest],
) (*connect.Response[organizationv1.CreateOrganizationResponse], error) {
	dto, err := h.facade.Create(ctx, &app.CreateInput{
		Name:        req.Msg.Name,
		DisplayName: req.Msg.DisplayName,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&organizationv1.CreateOrganizationResponse{
		Organization: dtoToProto(dto),
	}), nil
}

func (h *Handler) GetOrganization(
	ctx context.Context,
	req *connect.Request[organizationv1.GetOrganizationRequest],
) (*connect.Response[organizationv1.GetOrganizationResponse], error) {
	dto, err := h.facade.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&organizationv1.GetOrganizationResponse{
		Organization: dtoToProto(dto),
	}), nil
}

func (h *Handler) ListOrganizations(
	ctx context.Context,
	req *connect.Request[organizationv1.ListOrganizationsRequest],
) (*connect.Response[organizationv1.ListOrganizationsResponse], error) {
	out, err := h.facade.List(ctx, int(req.Msg.PageSize), req.Msg.PageToken)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	orgs := make([]*organizationv1.Organization, len(out.Organizations))
	for i, d := range out.Organizations {
		orgs[i] = dtoToProto(d)
	}

	return connect.NewResponse(&organizationv1.ListOrganizationsResponse{
		Organizations: orgs,
		NextPageToken: out.NextPageToken,
	}), nil
}
