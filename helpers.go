package cameradar

import "fmt"

func replace(devices []Device, new Device) []Device {
	var updatedSlice []Device

	for _, old := range devices {
		if old.Address == new.Address && old.Port == new.Port {
			updatedSlice = append(updatedSlice, new)
		} else {
			updatedSlice = append(updatedSlice, old)
		}
	}

	return updatedSlice
}

// GetCameraRTSPURL generates a device's RTSP URL.
func GetCameraRTSPURL(device Device) string {
	return "rtsp://" + device.Username + ":" + device.Password + "@" + device.Address + ":" + fmt.Sprint(device.Port) + "/" + device.Stream
}

// GetCameraAdminPanelURL returns the URL to the camera's admin panel.
func GetCameraAdminPanelURL(device Device) string {
	return "http://" + device.Address + "/"
}
