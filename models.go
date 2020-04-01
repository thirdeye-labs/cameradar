package cameradar

import "time"

// Device represents a camera's RTSP device
type Device struct {
	Device   string `json:"device"`
	Username string `json:"username"`
	Password string `json:"password"`
	Route    string `json:"route"`
	Address  string `json:"address" validate:"required"`
	Port     uint16 `json:"port" validate:"required"`

	CredentialsFound bool `json:"credentials_found"`
	RouteFound       bool `json:"route_found"`
	Available        bool `json:"available"`

	AuthenticationType int `json:"authentication_type"`
}

// Credentials is a map of credentials
// usernames are keys and passwords are values
// creds['admin'] -> 'secure_password'
type Credentials struct {
	Usernames []string `json:"usernames"`
	Passwords []string `json:"passwords"`
}

// Routes is a slice of Routes
// ['/live.sdp', '/media.amp', ...]
type Routes []string

// Options contains all options needed to launch a complete cameradar scan
type Options struct {
	Targets     []string      `json:"target" validate:"required"`
	Ports       []string      `json:"ports"`
	Routes      Routes        `json:"routes"`
	Credentials Credentials   `json:"credentials"`
	Speed       int           `json:"speed"`
	Timeout     time.Duration `json:"timeout"`
}
