package httptransport

import (
	"context"
	"log"
	"net/http"

	"kasper/internal/domain"
	"kasper/internal/service"
	api "kasper/internal/transport/http/openapi"
)

type ThreatService interface {
	Create(context.Context, service.CreateThreatInput) (domain.Threat, error)
	GetByMD5(context.Context, string) (domain.Threat, error)
	Update(context.Context, string, service.UpdateThreatInput) (domain.Threat, error)
}

type handler struct {
	service ThreatService
	logger  *log.Logger
}

var _ api.StrictServerInterface = (*handler)(nil)

func (h *handler) CreateThreat(ctx context.Context, request api.CreateThreatRequestObject) (api.CreateThreatResponseObject, error) {
	if request.Body == nil {
		return api.CreateThreat400JSONResponse(newErrorResponse("Invalid request", "Request body is required")), nil
	}
	input := service.CreateThreatInput{
		MD5:      request.Body.Md5,
		Name:     request.Body.Name,
		Severity: (*string)(request.Body.Severity),
	}
	if request.Body.Description != nil {
		input.Description = *request.Body.Description
	}
	item, err := h.service.Create(ctx, input)
	if err != nil {
		status, response := classifyError(err)
		switch status {
		case http.StatusBadRequest:
			return api.CreateThreat400JSONResponse(response), nil
		case http.StatusConflict:
			return api.CreateThreat409JSONResponse(response), nil
		default:
			return api.CreateThreat500JSONResponse(h.internalError(err)), nil
		}
	}
	return api.CreateThreat201JSONResponse(newThreatResponse(item)), nil
}

func (h *handler) GetInfoByMd5(ctx context.Context, request api.GetInfoByMd5RequestObject) (api.GetInfoByMd5ResponseObject, error) {
	item, err := h.service.GetByMD5(ctx, request.Md5)
	if err != nil {
		status, response := classifyError(err)
		switch status {
		case http.StatusBadRequest:
			return api.GetInfoByMd5400JSONResponse(response), nil
		case http.StatusNotFound:
			return api.GetInfoByMd5404JSONResponse(response), nil
		default:
			return api.GetInfoByMd5500JSONResponse(h.internalError(err)), nil
		}
	}
	return api.GetInfoByMd5200JSONResponse(newThreatResponse(item)), nil
}

func (h *handler) UpdateThreat(ctx context.Context, request api.UpdateThreatRequestObject) (api.UpdateThreatResponseObject, error) {
	if request.Body == nil {
		return api.UpdateThreat400JSONResponse(newErrorResponse("Invalid request", "Request body is required")), nil
	}
	input := service.UpdateThreatInput{
		Name:     request.Body.Name,
		Severity: (*string)(request.Body.Severity),
	}
	if request.Body.Description != nil {
		input.Description = *request.Body.Description
	}
	item, err := h.service.Update(ctx, request.Md5, input)
	if err != nil {
		status, response := classifyError(err)
		switch status {
		case http.StatusBadRequest:
			return api.UpdateThreat400JSONResponse(response), nil
		case http.StatusNotFound:
			return api.UpdateThreat404JSONResponse(response), nil
		default:
			return api.UpdateThreat500JSONResponse(h.internalError(err)), nil
		}
	}
	return api.UpdateThreat200JSONResponse(newThreatResponse(item)), nil
}
