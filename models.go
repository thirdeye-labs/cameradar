package cameradar

import "time"

// Stream represents a camera's RTSP stream
type Stream struct {
	Device   	string 			`json:"device"`
	Username 	string 			`json:"username"`
	Password 	string			`json:"password"`
	ValidRoutes	[]ValidRoute	`json:"route"`
	Address		string 			`json:"address" validate:"required"`
	Port 	    uint16 			`json:"port" validate:"required"`

	// Auth type set for the whole host and not for each Route. This should be always true most of the times. 
	// Having this set for the whole device should reduce scanning times 
	AuthenticationType int 		`json:"authentication_type"`
}


// Routes is a slice of Routes
// ['/live.sdp', '/media.amp', ...]
type Routes []string

type ValidRoute struct {
	Route				string 	`json:"route"`
	Available			bool 	`json:"available"`
	CredentialsFound 	bool 	`json:"credentials_found"`
}

// Options contains all options needed to launch a complete cameradar scan
type Options struct {
	Targets     []string      `json:"target" validate:"required"`
	Ports       []string      `json:"ports"`
	Routes      Routes        `json:"routes"`
	Speed       int           `json:"speed"`
	Timeout     time.Duration `json:"timeout"`
	Password	string        `json:"password"` 
	Username	string        `json:"username"` 
}
