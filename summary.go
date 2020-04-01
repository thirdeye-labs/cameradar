package cameradar

import (
	"github.com/Ullaakut/disgo/style"
	curl "github.com/Ullaakut/go-curl"
)

// Printeams prints information on each device.
func (s *Scanner) PrintDevices(devices []Device) {
	if len(devices) == 0 {
		s.term.Infof("%s No devices were found. Please make sure that your target is on an accessible network.\n", style.Failure(style.SymbolCross))
	}

	success := 0
	for _, device := range devices {
		if device.Available {
			s.term.Infof("%s\tDevice RTSP URL:\t%s\n", style.Success(style.SymbolRightTriangle), style.Link(GetCameraRTSPURL(device)))
			s.term.Infof("\tAvailable:\t\t%s\n", style.Success(style.SymbolCheck))
			success++
		} else {
			s.term.Infof("%s\tAdmin panel URL:\t%s You can use this URL to try attacking the camera's admin panel instead.\n", style.Failure(style.SymbolCross), style.Link(GetCameraAdminPanelURL(device)))
			s.term.Infof("\tAvailable:\t\t%s\n", style.Failure(style.SymbolCross))
		}

		if len(device.Device) > 0 {
			s.term.Infof("\tDevice model:\t\t%s\n\n", device.Device)
		}

		s.term.Infof("\tIP address:\t\t%s\n", device.Address)
		s.term.Infof("\tRTSP port:\t\t%d\n", device.Port)

		switch device.AuthenticationType {
		case curl.AUTH_NONE:
			s.term.Infoln("\tThis camera does not require authentication")
		case curl.AUTH_BASIC:
			s.term.Infoln("\tAuth type:\t\tbasic")
		case curl.AUTH_DIGEST:
			s.term.Infoln("\tAuth type:\t\tdigest")
		}

		if device.CredentialsFound {
			s.term.Infof("\tUsername:\t\t%s\n", style.Success(device.Username))
			s.term.Infof("\tPassword:\t\t%s\n", style.Success(device.Password))
		} else {
			s.term.Infof("\tUsername:\t\t%s\n", style.Failure("not found"))
			s.term.Infof("\tPassword:\t\t%s\n", style.Failure("not found"))
		}

		if device.StreamFound {
			s.term.Infof("\tRTSP stream:\t\t%s\n\n\n", style.Success("/"+device.Stream))
		} else {
			s.term.Infof("\tRTSP stream:\t\t%s\n\n\n", style.Failure("not found"))
		}
	}

	if success > 1 {
		s.term.Infof("%s Successful attack: %s devices were accessed", style.Success(style.SymbolCheck), style.Success(len(devices)))
	} else if success == 1 {
		s.term.Infof("%s Successful attack: %s device was accessed", style.Success(style.SymbolCheck), style.Success("one"))
	} else {
		s.term.Infof("%s Streams were found but none were accessed. They are most likely configured with secure credentials and streams. You can try adding entries to the dictionary or generating your own in order to attempt a bruteforce attack on the cameras.\n", style.Failure("\xE2\x9C\x96"))
	}
}
