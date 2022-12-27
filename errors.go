package caddyjwt

import "errors"

var (
	ErrMissingKeys          = errors.New("missing sign_key and jwk_url")
	ErrInvalidPublicKey     = errors.New("invalid PEM-formatted public key")
	ErrInvalidSignAlgorithm = errors.New("invalid sign_alg")
	ErrInvalidIssuer        = errors.New("invalid issuer")
	ErrInvalidAudience      = errors.New("invalid audience")
	ErrEmptyUserClaim       = errors.New("user claim is empty")
)
