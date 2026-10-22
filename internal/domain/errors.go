package domain

import "errors"

var (
	ErrInvalidMD5          = errors.New("MD5 must contain exactly 32 hexadecimal characters")
	ErrInvalidSeverity     = errors.New("severity must be one of: unknown, low, medium, high, critical")
	ErrInvalidText         = errors.New("invalid threat text")
	ErrThreatNotFound      = errors.New("threat not found")
	ErrThreatAlreadyExists = errors.New("threat already exists")
)
