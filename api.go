package caddyjwt

import (
	"errors"
	"net/http"

	"go.uber.org/zap"
)

type APIMode struct {
	Endpoint string `json:"endpoint"`
	Method   string `json:"method"`

	logger *zap.Logger
}

func (m *APIMode) validate() error {
	return nil
}

func (m *APIMode) Authenticate(rw http.ResponseWriter, r *http.Request) (User, bool, error) {
	return User{}, false, errors.New("not implemented")
}
