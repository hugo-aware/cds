package api

import (
	"context"
	"net/http"

	"github.com/ovh/cds/engine/service"
)

func (api *API) getDriversHandler() service.Handler {
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		return service.WriteJSON(w, api.ExternalDrivers, http.StatusOK)
	}
}
