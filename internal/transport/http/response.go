package httptransport

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"

	"kasper/internal/domain"
	api "kasper/internal/transport/http/openapi"
)

func newThreatResponse(item domain.Threat) api.ThreatResponse {
	severity := api.ThreatResponseSeverity(item.Severity)
	return api.ThreatResponse{
		Md5:         &item.MD5,
		Name:        &item.Name,
		Description: &item.Description,
		Severity:    &severity,
	}
}

func newErrorResponse(message, details string) api.ErrorResponse {
	response := api.ErrorResponse{Message: &message}
	if details != "" {
		response.Details = &details
	}
	return response
}

func classifyError(err error) (int, api.ErrorResponse) {
	var invalidRequest *requestError
	var bodyError *requestBodyError
	switch {
	case errors.As(err, &bodyError):
		var tooLarge *http.MaxBytesError
		var networkErr net.Error
		switch {
		case errors.As(bodyError, &tooLarge):
			return http.StatusRequestEntityTooLarge, newErrorResponse("Request body too large", fmt.Sprintf("Request body must not exceed %d bytes", tooLarge.Limit))
		case errors.As(bodyError, &networkErr) && networkErr.Timeout():
			return http.StatusRequestTimeout, newErrorResponse("Request timeout", "Request body was not received in time")
		default:
			return http.StatusBadRequest, newErrorResponse("Invalid request", "Could not read request body")
		}
	case errors.As(err, &invalidRequest):
		return http.StatusBadRequest, newErrorResponse("Invalid request", invalidRequest.Error())
	case errors.Is(err, domain.ErrInvalidMD5):
		return http.StatusBadRequest, newErrorResponse("Invalid MD5", domain.ErrInvalidMD5.Error())
	case errors.Is(err, domain.ErrInvalidSeverity):
		return http.StatusBadRequest, newErrorResponse("Invalid request", domain.ErrInvalidSeverity.Error())
	case errors.Is(err, domain.ErrInvalidText):
		return http.StatusBadRequest, newErrorResponse("Invalid request", err.Error())
	case errors.Is(err, domain.ErrThreatNotFound):
		return http.StatusNotFound, newErrorResponse("Threat not found", "No threat with this MD5 was found")
	case errors.Is(err, domain.ErrThreatAlreadyExists):
		return http.StatusConflict, newErrorResponse("Threat already exists", "A threat with this MD5 already exists")
	default:
		return http.StatusInternalServerError, newErrorResponse("Internal server error", "")
	}
}

func (h *handler) internalError(err error) api.ErrorResponse {
	h.logger.Printf("Request failed: %v", err)
	return newErrorResponse("Internal server error", "")
}

func (h *handler) writeError(w http.ResponseWriter, err error) {
	status, response := classifyError(err)
	if status == http.StatusInternalServerError {
		response = h.internalError(err)
	}
	h.writeJSON(w, status, response)
}

func (h *handler) writeJSON(w http.ResponseWriter, status int, value api.ErrorResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		h.logger.Printf("Could not write response: %v", err)
	}
}
