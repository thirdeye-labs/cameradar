package cameradar

import (
	"encoding/json"
	"fmt"

	"github.com/Ullaakut/disgo/style"
	curl "github.com/Ullaakut/go-curl"
)



// PrintStreams prints information on each stream.
func (s *Scanner) PrintStreams(streams []Stream) {
	if len(streams) == 0 {
		s.term.Infof("%s No streams were found. Please make sure that your target is on an accessible network.\n", style.Failure(style.SymbolCross))
	}

	// Print JSON
	streams_marshalled, err := json.MarshalIndent(streams, "", "	")
	if err != nil {
		fmt.Printf("Error: %s", err)
		return;
	}
	fmt.Printf(string(streams_marshalled))


	success := 0
	for _, stream := range streams {

		if len(stream.Device) > 0 {
			s.term.Infof("\tDevice model:\t\t%s\n\n", stream.Device)
		}

		s.term.Infof("\tIP address:\t\t%s\n", stream.Address)
		s.term.Infof("\tRTSP port:\t\t%d\n", stream.Port)

		switch stream.AuthenticationType {
		case curl.AUTH_NONE:
			s.term.Infoln("\tThis camera does not require authentication")
		case curl.AUTH_BASIC:
			s.term.Infoln("\tAuth type:\t\tbasic")
		case curl.AUTH_DIGEST:
			s.term.Infoln("\tAuth type:\t\tdigest")
		}


		if len(stream.ValidRoutes) > 0 {
			for _, route := range stream.ValidRoutes {
				s.term.Infof("\tRTSP route:\t\t%s\n", style.Success("/"+route.Route))
				if route.CredentialsFound {
					s.term.Infof("\t\tUsername:\t\t%s\n", style.Success(stream.Username))
					s.term.Infof("\t\tPassword:\t\t%s\n", style.Success(stream.Password))
				} else {
					s.term.Infof("\t\tUsername:\t\t%s\n", style.Failure("not found"))
					s.term.Infof("\t\tPassword:\t\t%s\n", style.Failure("not found"))
				}
				if route.Available {
					s.term.Infof("%s\tDevice RTSP URL:\t%s\n", style.Success(style.SymbolRightTriangle), style.Link(GetCameraRTSPURL(stream)+route.Route))
					s.term.Infof("\tAvailable:\t\t%s\n", style.Success(style.SymbolCheck))
					success++
				} else {
					s.term.Infof("\tAvailable:\t\t%s\n", style.Failure(style.SymbolCross))
				}
			}
			s.term.Infof("\n\n")
		} else {
			s.term.Infof("\tRTSP route:\t\t%s\n\n\n", style.Failure("not found"))
			s.term.Infof("\t\tUsername:\t\t%s\n", style.Failure("not found"))
			s.term.Infof("\t\tPassword:\t\t%s\n", style.Failure("not found"))
		}
	}

	if success > 1 {
		s.term.Infof("%s Successful attack: %s devices were accessed", style.Success(style.SymbolCheck), style.Success(len(streams)))
	} else if success == 1 {
		s.term.Infof("%s Successful attack: %s device was accessed", style.Success(style.SymbolCheck), style.Success("one"))
	} else {
		s.term.Infof("%s Streams were found but none were accessed. They are most likely configured with secure credentials and routes. You can try adding entries to the dictionary or generating your own in order to attempt a bruteforce attack on the cameras.\n", style.Failure("\xE2\x9C\x96"))
	}
}
