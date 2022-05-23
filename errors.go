package caddyjwt

import "errors"

var (
	ErrMissingSignKey   = errors.New("sign_key is required")
	ErrInvalidPublicKey = errors.New("invalid PEM-formatted public key")
	ErrInvalidIssuer    = errors.New("invalid issuer")
	ErrInvalidAudience  = errors.New("invalid audience")
	ErrEmptyUserClaim   = errors.New("user claim is empty")
)
