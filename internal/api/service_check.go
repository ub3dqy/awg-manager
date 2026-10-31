package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/hoaxisr/awg-manager/internal/response"
	"github.com/hoaxisr/awg-manager/internal/servicecheck"
)

type serviceChecker interface {
	Options(context.Context) (servicecheck.Options, error)
	Run(context.Context, servicecheck.Request) (servicecheck.Report, error)
}

type ServiceCheckHandler struct{ svc serviceChecker }

func NewServiceCheckHandler(svc serviceChecker) *ServiceCheckHandler {
	return &ServiceCheckHandler{svc: svc}
}

type ServiceCheckOptionsEnvelope struct {
	Success bool                 `json:"success"`
	Data    servicecheck.Options `json:"data"`
}

type ServiceCheckReportEnvelope struct {
	Success bool                `json:"success"`
	Data    servicecheck.Report `json:"data"`
}

// Options lists devices, DNS profiles and interfaces for a read-only diagnostic.
//
// @Summary Service diagnostic choices
// @Tags diagnostics
// @Produce json
// @Security CookieAuth
// @Success 200 {object} ServiceCheckOptionsEnvelope
// @Failure 503 {object} APIErrorEnvelope
// @Router /diagnostics/service/options [get]
func (h *ServiceCheckHandler) Options(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		response.MethodNotAllowed(w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	x, err := h.svc.Options(ctx)
	if err != nil {
		response.ErrorWithStatus(w, http.StatusServiceUnavailable, "Diagnostic data unavailable", "SERVICE_CHECK_UNAVAILABLE")
		return
	}
	response.Success(w, x)
}

// Run queries the selected local policy DNS listener, matches routing lists and
// reads a connection snapshot. An optional TCP connect is bound to an explicitly
// selected interface. No config, restart, IP-host probe or packet capture is used.
//
// @Summary Diagnose a client and destination without changing settings
// @Tags diagnostics
// @Accept json
// @Produce json
// @Security CookieAuth
// @Param body body servicecheck.Request true "Device and destination"
// @Success 200 {object} ServiceCheckReportEnvelope
// @Failure 400 {object} APIErrorEnvelope
// @Failure 409 {object} APIErrorEnvelope
// @Failure 503 {object} APIErrorEnvelope
// @Router /diagnostics/service/run [post]
func (h *ServiceCheckHandler) Run(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response.MethodNotAllowed(w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	var input servicecheck.Request
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		response.BadRequest(w, "Invalid diagnostic request")
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		response.BadRequest(w, "Expected one diagnostic request")
		return
	}
	x, err := h.svc.Run(r.Context(), input)
	if err != nil {
		switch {
		case errors.Is(err, servicecheck.ErrInput):
			response.BadRequest(w, "Choose a known device, DNS profile and valid destination/port")
		case errors.Is(err, servicecheck.ErrBusy):
			response.ErrorWithStatus(w, http.StatusConflict, "Service diagnostics already running", "SERVICE_CHECK_BUSY")
		default:
			response.ErrorWithStatus(w, http.StatusServiceUnavailable, "Diagnostic data unavailable or check cancelled", "SERVICE_CHECK_UNAVAILABLE")
		}
		return
	}
	response.Success(w, x)
}
