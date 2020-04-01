package cameradar

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReplace(t *testing.T) {
	validDevice1 := Device{
		Device:  "fakeDevice",
		Address: "fakeAddress",
		Port:    1,
	}

	validDevice2 := Device{
		Device:  "fakeDevice",
		Address: "differentFakeAddress",
		Port:    2,
	}

	invalidDevice := Device{
		Device:  "invalidDevice",
		Address: "anotherFakeAddress",
		Port:    3,
	}

	invalidDeviceModified := Device{
		Device:  "updatedDevice",
		Address: "anotherFakeAddress",
		Port:    3,
	}

	testCases := []struct {
		devices   []Device
		newDevice Device

		expectedDevices []Device
	}{
		{
			devices:   []Device{validDevice1, validDevice2, invalidDevice},
			newDevice: invalidDeviceModified,

			expectedDevices: []Device{validDevice1, validDevice2, invalidDeviceModified},
		},
	}

	for _, test := range testCases {
		devices := replace(test.devices, test.newDevice)

		assert.Equal(t, len(test.expectedDevices), len(devices))

		for _, expectedDevice := range test.expectedDevices {
			assert.Contains(t, devices, expectedDevice)
		}
	}
}

func TestGetCameraRTSPURL(t *testing.T) {
	validDevice := Device{
		Address:  "1.2.3.4",
		Username: "ullaakut",
		Password: "ba69897483886f0d2b0afb6345b76c0c",
		Route:    "cameradar.sdp",
		Port:     1337,
	}

	testCases := []struct {
		device Device

		expectedRTSPURL string
	}{
		{
			device: validDevice,

			expectedRTSPURL: "rtsp://ullaakut:ba69897483886f0d2b0afb6345b76c0c@1.2.3.4:1337/cameradar.sdp",
		},
	}

	for _, test := range testCases {
		assert.Equal(t, test.expectedRTSPURL, GetCameraRTSPURL(test.device))
	}
}

func TestGetCameraAdminPanelURL(t *testing.T) {
	validDevice := Device{
		Address: "1.2.3.4",
	}

	testCases := []struct {
		device Device

		expectedRTSPURL string
	}{
		{
			device: validDevice,

			expectedRTSPURL: "http://1.2.3.4/",
		},
	}

	for _, test := range testCases {
		assert.Equal(t, test.expectedRTSPURL, GetCameraAdminPanelURL(test.device))
	}
}
