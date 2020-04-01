package cameradar

import (
	"errors"
	"io/ioutil"
	"os"
	"testing"

	"github.com/Ullaakut/disgo"

	"github.com/Ullaakut/nmap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type nmapMock struct {
	mock.Mock
}

func (m *nmapMock) Run() (*nmap.Run, []string, error) {
	args := m.Called()

	if args.Get(0) != nil && args.Get(1) != nil {
		return args.Get(0).(*nmap.Run), args.Get(1).([]string), args.Error(2)
	}
	return nil, nil, args.Error(2)
}

var (
	validDevice1 = Device{
		Device:  "fakeDevice",
		Address: "fakeAddress",
		Port:    1337,
	}

	validDevice2 = Device{
		Device:  "fakeDevice",
		Address: "differentFakeAddress",
		Port:    1337,
	}

	invalidDeviceNoPort = Device{
		Device:  "invalidDevice",
		Address: "fakeAddress",
		Port:    0,
	}

	invalidDeviceNoAddress = Device{
		Device:  "invalidDevice",
		Address: "",
		Port:    1337,
	}
)

func TestScan(t *testing.T) {
	tests := []struct {
		description string

		targets    []string
		ports      []string
		speed      int
		removePath bool

		expectedErr     error
		expectedDevices []Device
	}{
		{
			description: "create new scanner and call scan, no error",

			targets: []string{"localhost"},
			ports:   []string{"80"},
			speed:   5,
		},
		{
			description: "create new scanner with missing nmap installation",

			removePath: true,
			ports:      []string{"80"},

			expectedErr: errors.New("unable to create network scanner: nmap binary was not found"),
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			if test.removePath {
				os.Setenv("PATH", "")
			}

			scanner := &Scanner{
				term:      disgo.NewTerminal(disgo.WithDefaultOutput(ioutil.Discard)),
				targets:   test.targets,
				ports:     test.ports,
				scanSpeed: test.speed,
			}

			result, err := scanner.Scan()

			assert.Equal(t, test.expectedErr, err)
			assert.Equal(t, test.expectedDevices, result)
		})
	}
}

func TestInternalScan(t *testing.T) {

	tests := []struct {
		description string

		nmapResult   *nmap.Run
		nmapWarnings []string
		nmapError    error

		expectedDevices []Device
		expectedErr     error
	}{
		{
			description: "valid devices",

			nmapResult: &nmap.Run{
				Hosts: []nmap.Host{
					{
						Addresses: []nmap.Address{
							{
								Addr: validDevice1.Address,
							},
						},
						Ports: []nmap.Port{
							{
								State: nmap.State{
									State: "open",
								},
								ID: validDevice1.Port,
								Service: nmap.Service{
									Name:    "rtsp",
									Product: validDevice1.Device,
								},
							},
						},
					},
					{
						Addresses: []nmap.Address{
							{
								Addr: validDevice2.Address,
							},
						},
						Ports: []nmap.Port{
							{
								State: nmap.State{
									State: "open",
								},
								ID: validDevice2.Port,
								Service: nmap.Service{
									Name:    "rtsp-alt",
									Product: validDevice2.Device,
								},
							},
						},
					},
				},
			},

			expectedDevices: []Device{validDevice1, validDevice2},
		},
		{
			description: "two invalid targets, no error",

			nmapResult: &nmap.Run{
				Hosts: []nmap.Host{
					{
						Addresses: []nmap.Address{
							{
								Addr: invalidDeviceNoPort.Address,
							},
						},
					},
					{
						Addresses: []nmap.Address{},
						Ports: []nmap.Port{
							{
								State: nmap.State{
									State: "open",
								},
								ID: validDevice2.Port,
								Service: nmap.Service{
									Name:    "rtsp-alt",
									Product: invalidDeviceNoAddress.Device,
								},
							},
						},
					},
				},
			},

			expectedDevices: nil,
		},
		{
			description: "different port states, no error",

			nmapResult: &nmap.Run{
				Hosts: []nmap.Host{
					{
						Addresses: []nmap.Address{
							{
								Addr: invalidDeviceNoPort.Address,
							}},
						Ports: []nmap.Port{
							{
								State: nmap.State{
									State: "closed",
								},
								ID: validDevice2.Port,
								Service: nmap.Service{
									Name:    "rtsp-alt",
									Product: invalidDeviceNoAddress.Device,
								},
							},
						},
					},
					{
						Addresses: []nmap.Address{
							{
								Addr: invalidDeviceNoPort.Address,
							}},
						Ports: []nmap.Port{
							{
								State: nmap.State{
									State: "unfiltered",
								},
								ID: validDevice2.Port,
								Service: nmap.Service{
									Name:    "rtsp-alt",
									Product: invalidDeviceNoAddress.Device,
								},
							},
						},
					},
					{
						Addresses: []nmap.Address{
							{
								Addr: invalidDeviceNoPort.Address,
							}},
						Ports: []nmap.Port{
							{
								State: nmap.State{
									State: "filtered",
								},
								ID: validDevice2.Port,
								Service: nmap.Service{
									Name:    "rtsp-alt",
									Product: invalidDeviceNoAddress.Device,
								},
							},
						},
					},
				},
			},

			expectedDevices: nil,
		},
		{
			description: "not rtsp, no error",

			nmapResult: &nmap.Run{
				Hosts: []nmap.Host{
					{
						Addresses: []nmap.Address{
							{
								Addr: invalidDeviceNoPort.Address,
							}},
						Ports: []nmap.Port{
							{
								State: nmap.State{
									State: "open",
								},
								ID: validDevice2.Port,
								Service: nmap.Service{
									Name:    "tcp",
									Product: invalidDeviceNoAddress.Device,
								},
							},
						},
					},
				},
			},

			expectedDevices: nil,
		},
		{
			description: "no hosts found",

			nmapResult:      &nmap.Run{},
			expectedDevices: nil,
		},
		{
			description: "scan failed",

			nmapError:    errors.New("scan failed"),
			nmapWarnings: []string{"invalid host"},
			expectedErr:  errors.New("error while scanning network: scan failed"),
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			nmapMock := &nmapMock{}

			nmapMock.On("Run").Return(test.nmapResult, test.nmapWarnings, test.nmapError)

			scanner := &Scanner{
				term: disgo.NewTerminal(disgo.WithDefaultOutput(ioutil.Discard)),
			}

			results, err := scanner.scan(nmapMock)

			assert.Equal(t, test.expectedErr, err)
			assert.Equal(t, test.expectedDevices, results, "wrong devices parsed")
			assert.Equal(t, len(test.expectedDevices), len(results), "wrong devices parsed")

			nmapMock.AssertExpectations(t)
		})
	}
}
