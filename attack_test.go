package cameradar

import (
	"errors"
	"io/ioutil"
	"testing"
	"time"

	"github.com/Ullaakut/disgo"
	curl "github.com/Ullaakut/go-curl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type CurlerMock struct {
	mock.Mock
}

func (m *CurlerMock) Setopt(opt int, param interface{}) error {
	args := m.Called(opt, param)
	return args.Error(0)
}

func (m *CurlerMock) Perform() error {
	args := m.Called()
	return args.Error(0)
}

func (m *CurlerMock) Getinfo(info curl.CurlInfo) (interface{}, error) {
	args := m.Called(info)
	return args.Int(0), args.Error(1)
}

func (m *CurlerMock) Duphandle() Curler {
	return m
}

func TestAttack(t *testing.T) {
	var (
		device1 = Device{
			Device:  "fakeDevice",
			Address: "fakeAddress",
			Port:    1337,
		}

		device2 = Device{
			Device:  "fakeDevice",
			Address: "differentFakeAddress",
			Port:    1337,
		}

		fakeTargets     = []Device{device1, device2}
		fakeStreams      = Streams{"live.sdp", "media.amp"}
		fakeCredentials = Credentials{
			Usernames: []string{"admin", "root"},
			Passwords: []string{"12345", "root"},
		}
	)

	tests := []struct {
		description string

		targets []Device

		performErr error

		expectedDevices []Device
		expectedErr     error
	}{
		{
			description: "inverted RTSP RFC",

			targets: fakeTargets,

			performErr: errors.New("dummy error"),

			expectedDevices: fakeTargets,
		},
		{
			description: "attack works",

			targets: fakeTargets,

			expectedDevices: fakeTargets,
		},
		{
			description: "no targets",

			targets: nil,

			expectedDevices: nil,
			expectedErr:     errors.New("unable to attack empty list of targets"),
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			curlerMock := &CurlerMock{}

			if len(test.targets) != 0 {
				curlerMock.On("Setopt", mock.Anything, mock.Anything).Return(nil)
				curlerMock.On("Perform").Return(test.performErr)
				if test.performErr == nil {
					curlerMock.On("Getinfo", mock.Anything).Return(200, nil)
				}
			}

			scanner := &Scanner{
				term:        disgo.NewTerminal(disgo.WithDefaultOutput(ioutil.Discard)),
				curl:        curlerMock,
				timeout:     time.Millisecond,
				verbose:     false,
				credentials: fakeCredentials,
				streams:      fakeStreams,
			}

			results, err := scanner.Attack(test.targets)

			assert.Equal(t, test.expectedErr, err)

			assert.Len(t, results, len(test.expectedDevices))

			curlerMock.AssertExpectations(t)
		})
	}
}

func TestAttackCredentials(t *testing.T) {
	var (
		device1 = Device{
			Device:    "fakeDevice",
			Address:   "fakeAddress",
			Port:      1337,
			Available: true,
		}

		device2 = Device{
			Device:    "fakeDevice",
			Address:   "differentFakeAddress",
			Port:      1337,
			Available: true,
		}

		fakeTargets     = []Device{device1, device2}
		fakeCredentials = Credentials{
			Usernames: []string{"admin", "root"},
			Passwords: []string{"12345", "root"},
		}
	)

	tests := []struct {
		description string

		targets     []Device
		credentials Credentials
		timeout     time.Duration
		verbose     bool

		status int

		performErr     error
		getInfoErr     error
		invalidTargets bool

		expectedDevices []Device
	}{
		{
			description: "Credentials found",

			targets:     fakeTargets,
			credentials: fakeCredentials,
			timeout:     1 * time.Millisecond,

			status: 404,

			expectedDevices: fakeTargets,
		},
		{
			description: "Camera accessed",

			targets:     fakeTargets,
			credentials: fakeCredentials,
			timeout:     1 * time.Millisecond,

			status: 200,

			expectedDevices: fakeTargets,
		},
		{
			description: "curl perform fails",

			targets:     fakeTargets,
			credentials: fakeCredentials,
			timeout:     1 * time.Millisecond,

			performErr: errors.New("dummy error"),

			expectedDevices: fakeTargets,
		},
		{
			description: "curl getinfo fails",

			targets:     fakeTargets,
			credentials: fakeCredentials,
			timeout:     1 * time.Millisecond,

			getInfoErr: errors.New("dummy error"),

			expectedDevices: fakeTargets,
		},
		{
			description: "Verbose mode disabled",

			targets:     fakeTargets,
			credentials: fakeCredentials,
			timeout:     1 * time.Millisecond,
			verbose:     false,

			status: 403,

			expectedDevices: fakeTargets,
		},
		{
			description: "Verbose mode enabled",

			targets:     fakeTargets,
			credentials: fakeCredentials,
			timeout:     1 * time.Millisecond,
			verbose:     true,

			status: 403,

			expectedDevices: fakeTargets,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			curlerMock := &CurlerMock{}

			if !test.invalidTargets {
				curlerMock.On("Setopt", mock.Anything, mock.Anything).Return(nil)
				curlerMock.On("Perform").Return(test.performErr)
				if test.performErr == nil {
					curlerMock.On("Getinfo", mock.Anything).Return(test.status, test.getInfoErr)
				}
			}

			scanner := &Scanner{
				term:        disgo.NewTerminal(disgo.WithDefaultOutput(ioutil.Discard)),
				curl:        curlerMock,
				timeout:     test.timeout,
				verbose:     test.verbose,
				credentials: test.credentials,
			}

			results := scanner.AttackCredentials(test.targets)

			assert.Len(t, results, len(test.expectedDevices))

			curlerMock.AssertExpectations(t)
		})
	}
}

func TestAttackStream(t *testing.T) {
	var (
		device1 = Device{
			Device:    "fakeDevice",
			Address:   "fakeAddress",
			Port:      1337,
			Available: true,
		}

		device2 = Device{
			Device:    "fakeDevice",
			Address:   "differentFakeAddress",
			Port:      1337,
			Available: true,
		}

		fakeTargets = []Device{device1, device2}
		fakeStreams  = Streams{"live.sdp", "media.amp"}
	)

	tests := []struct {
		description string

		targets []Device
		streams  Streams
		timeout time.Duration
		verbose bool

		status int

		performErr     error
		getInfoErr     error
		invalidTargets bool

		expectedDevices []Device
		expectedErr     error
	}{
		{
			description: "Stream found",

			targets: fakeTargets,
			streams:  fakeStreams,
			timeout: 1 * time.Millisecond,

			status: 403,

			expectedDevices: fakeTargets,
		},
		{
			description: "Stream found",

			targets: fakeTargets,
			streams:  fakeStreams,
			timeout: 1 * time.Millisecond,

			status: 401,

			expectedDevices: fakeTargets,
		},
		{
			description: "Camera accessed",

			targets: fakeTargets,
			streams:  fakeStreams,
			timeout: 1 * time.Millisecond,

			status: 200,

			expectedDevices: fakeTargets,
		},
		{
			description: "curl perform fails",

			targets: fakeTargets,
			streams:  fakeStreams,
			timeout: 1 * time.Millisecond,

			performErr: errors.New("dummy error"),

			expectedDevices: fakeTargets,
		},
		{
			description: "curl getinfo fails",

			targets: fakeTargets,
			streams:  fakeStreams,
			timeout: 1 * time.Millisecond,

			getInfoErr: errors.New("dummy error"),

			expectedDevices: fakeTargets,
		},
		{
			description: "verbose mode disabled",

			targets: fakeTargets,
			streams:  fakeStreams,
			timeout: 1 * time.Millisecond,
			verbose: false,

			expectedDevices: fakeTargets,
		},
		{
			description: "verbose mode enabled",

			targets: fakeTargets,
			streams:  fakeStreams,
			timeout: 1 * time.Millisecond,
			verbose: true,

			expectedDevices: fakeTargets,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			curlerMock := &CurlerMock{}

			if !test.invalidTargets {
				curlerMock.On("Setopt", mock.Anything, mock.Anything).Return(nil)
				curlerMock.On("Perform").Return(test.performErr)
				if test.performErr == nil {
					curlerMock.On("Getinfo", mock.Anything).Return(test.status, test.getInfoErr)
				}
			}

			scanner := &Scanner{
				term:    disgo.NewTerminal(disgo.WithDefaultOutput(ioutil.Discard)),
				curl:    curlerMock,
				timeout: test.timeout,
				verbose: test.verbose,
				streams:  test.streams,
			}

			results := scanner.AttackStream(test.targets)

			assert.Len(t, results, len(test.expectedDevices))

			curlerMock.AssertExpectations(t)
		})
	}
}

func TestValidateDevices(t *testing.T) {
	var (
		device1 = Device{
			Device:    "fakeDevice",
			Address:   "fakeAddress",
			Port:      1337,
			Available: true,
		}

		device2 = Device{
			Device:    "fakeDevice",
			Address:   "differentFakeAddress",
			Port:      1337,
			Available: true,
		}

		fakeTargets = []Device{device1, device2}
	)

	tests := []struct {
		description string

		targets []Device
		timeout time.Duration
		verbose bool

		status int

		performErr error
		getInfoErr error

		expectedDevices []Device
	}{
		{
			description: "stream found",

			targets: fakeTargets,
			timeout: 1 * time.Millisecond,

			status: 403,

			expectedDevices: fakeTargets,
		},
		{
			description: "stream found",

			targets: fakeTargets,
			timeout: 1 * time.Millisecond,

			status: 401,

			expectedDevices: fakeTargets,
		},
		{
			description: "camera accessed",

			targets: fakeTargets,
			timeout: 1 * time.Millisecond,

			status: 200,

			expectedDevices: fakeTargets,
		},
		{
			description: "unavailable device",

			targets: fakeTargets,
			timeout: 1 * time.Millisecond,

			status: 400,

			expectedDevices: fakeTargets,
		},
		{
			description: "curl perform fails",

			targets: fakeTargets,
			timeout: 1 * time.Millisecond,

			performErr: errors.New("dummy error"),

			expectedDevices: fakeTargets,
		},
		{
			description: "curl getinfo fails",

			targets: fakeTargets,
			timeout: 1 * time.Millisecond,

			getInfoErr: errors.New("dummy error"),

			expectedDevices: fakeTargets,
		},
		{
			description: "verbose disabled",

			targets: fakeTargets,
			timeout: 1 * time.Millisecond,
			verbose: false,

			expectedDevices: fakeTargets,
		},
		{
			description: "verbose enabled",

			targets: fakeTargets,
			timeout: 1 * time.Millisecond,
			verbose: true,

			expectedDevices: fakeTargets,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			curlerMock := &CurlerMock{}

			curlerMock.On("Setopt", mock.Anything, mock.Anything).Return(nil)
			curlerMock.On("Perform").Return(test.performErr)
			if test.performErr == nil {
				curlerMock.On("Getinfo", mock.Anything).Return(test.status, test.getInfoErr)
			}

			scanner := &Scanner{
				term:    disgo.NewTerminal(disgo.WithDefaultOutput(ioutil.Discard)),
				curl:    curlerMock,
				timeout: test.timeout,
				verbose: test.verbose,
			}

			results := scanner.ValidateDevices(test.targets)

			assert.Equal(t, len(test.expectedDevices), len(results))

			for _, expectedDevice := range test.expectedDevices {
				assert.Contains(t, results, expectedDevice)
			}

			curlerMock.AssertExpectations(t)
		})
	}
}

func TestDetectAuthenticationType(t *testing.T) {
	var (
		device1 = Device{
			Device:    "fakeDevice",
			Address:   "fakeAddress",
			Port:      1337,
			Available: true,
		}

		device2 = Device{
			Device:    "fakeDevice",
			Address:   "differentFakeAddress",
			Port:      1337,
			Available: true,
		}

		fakeTargets = []Device{device1, device2}
	)

	tests := []struct {
		description string

		targets []Device
		timeout time.Duration
		verbose bool

		status int

		performErr error
		getInfoErr error

		expectedDevices []Device
	}{
		{
			description: "no auth enabled",

			targets: fakeTargets,
			timeout: 1 * time.Millisecond,

			status: 0,

			expectedDevices: fakeTargets,
		},
		{
			description: "basic auth enabled",

			targets: fakeTargets,
			timeout: 1 * time.Millisecond,

			status: 1,

			expectedDevices: fakeTargets,
		},
		{
			description: "digest auth enabled",

			targets: fakeTargets,
			timeout: 1 * time.Millisecond,

			status: 2,

			expectedDevices: fakeTargets,
		},
		{
			description: "curl getinfo fails",

			targets: fakeTargets,
			timeout: 1 * time.Millisecond,

			getInfoErr: errors.New("dummy error"),

			expectedDevices: fakeTargets,
		},
		{
			description: "curl perform fails",

			targets: fakeTargets,
			timeout: 1 * time.Millisecond,

			performErr: errors.New("dummy error"),

			expectedDevices: fakeTargets,
		},
		{
			description: "verbose disabled",

			targets: fakeTargets,
			timeout: 1 * time.Millisecond,
			verbose: false,

			expectedDevices: fakeTargets,
		},
		{
			description: "verbose enabled",

			targets: fakeTargets,
			timeout: 1 * time.Millisecond,
			verbose: true,

			expectedDevices: fakeTargets,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			curlerMock := &CurlerMock{}

			curlerMock.On("Setopt", mock.Anything, mock.Anything).Return(nil)
			curlerMock.On("Perform").Return(test.performErr)
			if test.performErr == nil {
				curlerMock.On("Getinfo", mock.Anything).Return(test.status, test.getInfoErr)
			}

			scanner := &Scanner{
				term:    disgo.NewTerminal(disgo.WithDefaultOutput(ioutil.Discard)),
				curl:    curlerMock,
				timeout: test.timeout,
				verbose: test.verbose,
			}

			results := scanner.DetectAuthMethods(test.targets)

			assert.Equal(t, len(test.expectedDevices), len(results))

			for _, expectedDevice := range test.expectedDevices {
				assert.Contains(t, results, expectedDevice)
			}

			curlerMock.AssertExpectations(t)
		})
	}
}

func TestDoNotWrite(t *testing.T) {
	assert.Equal(t, true, doNotWrite(nil, nil))
}
