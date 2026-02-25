package organization

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	app "github.com/kaitobq/oauth21-oidc-idp/backend/internal/application/organization"
	domain "github.com/kaitobq/oauth21-oidc-idp/backend/internal/domain/organization"
	organizationv1 "github.com/kaitobq/oauth21-oidc-idp/backend/internal/gen/organization/v1"
	"github.com/kaitobq/oauth21-oidc-idp/backend/internal/gen/organization/v1/organizationv1connect"
)

// Handler implements the OrganizationService Connect RPC service.
type Handler struct {
	facade        *app.Facade
	actorResolver *actorResolver
}

var _ organizationv1connect.OrganizationServiceHandler = (*Handler)(nil)

// NewHandler creates a new Organization handler.
func NewHandler(facade *app.Facade) *Handler {
	return NewHandlerWithAuth(facade, AuthConfig{
		Mode: OrganizationAuthModeHeader,
	})
}

func NewHandlerWithAuth(facade *app.Facade, authConfig AuthConfig) *Handler {
	return &Handler{
		facade:        facade,
		actorResolver: newActorResolver(authConfig),
	}
}

func (h *Handler) CreateOrganization(
	ctx context.Context,
	req *connect.Request[organizationv1.CreateOrganizationRequest],
) (*connect.Response[organizationv1.CreateOrganizationResponse], error) {
	actor, err := h.actorResolver.Resolve(req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}

	name, err := domain.NewName(req.Msg.Name)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	displayName, err := domain.NewDisplayName(req.Msg.DisplayName)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	dto, err := h.facade.Create(ctx, actor, &app.CreateInput{
		Name:        name,
		DisplayName: displayName,
	})
	if err != nil {
		return nil, connect.NewError(mapAppErrorCode(err), err)
	}

	return connect.NewResponse(&organizationv1.CreateOrganizationResponse{
		Organization: dtoToProto(dto),
	}), nil
}

func (h *Handler) GetOrganization(
	ctx context.Context,
	req *connect.Request[organizationv1.GetOrganizationRequest],
) (*connect.Response[organizationv1.GetOrganizationResponse], error) {
	actor, err := h.actorResolver.Resolve(req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}

	id, err := domain.ParseID(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	dto, err := h.facade.Get(ctx, actor, id)
	if err != nil {
		return nil, connect.NewError(mapAppErrorCode(err), err)
	}

	return connect.NewResponse(&organizationv1.GetOrganizationResponse{
		Organization: dtoToProto(dto),
	}), nil
}

func (h *Handler) ListOrganizations(
	ctx context.Context,
	req *connect.Request[organizationv1.ListOrganizationsRequest],
) (*connect.Response[organizationv1.ListOrganizationsResponse], error) {
	actor, err := h.actorResolver.Resolve(req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}

	if req.Msg.PageSize < 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("page_size must be >= 0"))
	}
	out, err := h.facade.List(ctx, actor, int(req.Msg.PageSize), req.Msg.PageToken)
	if err != nil {
		return nil, connect.NewError(mapAppErrorCode(err), err)
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

func mapAppErrorCode(err error) connect.Code {
	switch {
	case errors.Is(err, app.ErrUnauthenticated):
		return connect.CodeUnauthenticated
	case errors.Is(err, app.ErrPermissionDenied):
		return connect.CodePermissionDenied
	default:
		return connect.CodeInternal
	}
}
