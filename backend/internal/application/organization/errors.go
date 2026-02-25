package organization

import "errors"

var (
	ErrUnauthenticated  = errors.New("organization: unauthenticated actor")
	ErrPermissionDenied = errors.New("organization: permission denied")
)
