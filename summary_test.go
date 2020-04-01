package cameradar

import (
	"bytes"
	"testing"

	"github.com/Ullaakut/disgo"
	"github.com/stretchr/testify/assert"
)

var (
	unavailable = Device{}

	available = Device{
		Available: true,
	}

	deviceFound = Device{
		Device: "devicename",
	}

	noAuth = Device{
		AuthenticationType: 0,
	}

	basic = Device{
		AuthenticationType: 1,
	}

	digest = Device{
		AuthenticationType: 2,
	}

	credsFound = Device{
		CredentialsFound: true,
		Username:         "us3r",
		Password:         "p4ss",
	}

	routeFound = Device{
		RouteFound: true,
		Route:      "r0ute",
	}
)

func TestPrintDevices(t *testing.T) {
	tests := []struct {
		description string

		devices []Device

		expectedLogs []string
	}{
		{
			description: "displays the proper message when no devices found",

			devices: nil,

			expectedLogs: []string{"No devices were found"},
		},
		{
			description: "displays the admin panel URL when a device is not accessible",

			devices: []Device{
				unavailable,
			},

			expectedLogs: []string{"Admin panel URL"},
		},
		{
			description: "displays the device name when it is found",

			devices: []Device{
				deviceFound,
			},

			expectedLogs: []string{"Device model:"},
		},
		{
			description: "displays authentication type (no auth)",

			devices: []Device{
				noAuth,
			},

			expectedLogs: []string{"This camera does not require authentication"},
		},
		{
			description: "displays authentication type (basic)",

			devices: []Device{
				basic,
			},

			expectedLogs: []string{"basic"},
		},
		{
			description: "displays authentication type (digest)",

			devices: []Device{
				digest,
			},

			expectedLogs: []string{"digest"},
		},
		{
			description: "displays credentials properly",

			devices: []Device{
				credsFound,
			},

			expectedLogs: []string{
				"Username",
				"us3r",
				"Password",
				"p4ss",
			},
		},
		{
			description: "displays route properly",

			devices: []Device{
				routeFound,
			},

			expectedLogs: []string{
				"RTSP route",
				"/r0ute",
			},
		},
		{
			description: "displays successes properly (no success)",

			devices: []Device{
				unavailable,
			},

			expectedLogs: []string{
				"Devices were found but none were accessed",
			},
		},
		{
			description: "displays successes properly (1 success)",

			devices: []Device{
				available,
			},

			expectedLogs: []string{
				"Successful attack",
				"device was accessed",
			},
		},
		{
			description: "displays successes properly (multiple successes)",

			devices: []Device{
				available,
				available,
				available,
				available,
			},

			expectedLogs: []string{
				"Successful attack",
				"devices were accessed",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			writer := &bytes.Buffer{}
			scanner := &Scanner{
				term: disgo.NewTerminal(disgo.WithDefaultOutput(writer)),
			}

			scanner.PrintDevices(test.devices)

			for _, expectedLog := range test.expectedLogs {
				assert.Contains(t, writer.String(), expectedLog)
			}
		})
	}
}
