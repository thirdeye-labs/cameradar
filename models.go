package cameradar

import "time"

// Device represents a camera's RTSP device
type Device struct {
	Device			string			`json:"device"`
	Username		string 			`json:"username"`
	Password 		string			`json:"password"`
	RtspStreams		[]rtspStream	`json:"rtspStreams"`
	Address			string			`json:"address" validate:"required"`
	Port			uint16			`json:"port" validate:"required"`
}

type rtspStream struct {
	Stream				string `json:"stream"`
	CredentialsFound	bool `json:"credentialsFound"`
	Available			bool `json:"available"`
	AuthenticationType	int `json:"authenticationType"`
	ImageUrl			string `json:"imageUrl"`
}

// Streams is a slice of Streams
// ['/live.sdp', '/media.amp', ...]
type Streams []string

// Options contains all options needed to launch a complete cameradar scan
type Options struct {
	Targets     []string      `json:"target" validate:"required"`
	Ports       []string      `json:"ports"`
	Streams      Streams        `json:"streams"`
	Speed       int           `json:"speed"`
	Timeout     time.Duration `json:"timeout"`
	Password	string        `json:"password"` 
	Username	string        `json:"username"` 
}
