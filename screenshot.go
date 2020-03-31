package cameradar

import (
//	"log"
	"os/exec"
	"fmt"
	"strings"
//	"github.com/spreadspace/go-gstreamer"
)

func (s *Scanner)makeScreenshots (targets []Stream) []Stream {
	resChan := make(chan Stream)
	defer close(resChan)

	for _, target := range targets {
		go makeScreenshot(target, resChan)
	}
	screenshotResults := []Stream{}
	for range targets {
		screenshotResults = append(screenshotResults, <-resChan)
	}
	return screenshotResults
}


func makeScreenshot(target Stream, resChan chan<- Stream){
	for i, validRoute := range target.ValidRoutes {
		if validRoute.CredentialsFound {
			file := fmt.Sprintf("%s_%s.jpg", strings.ReplaceAll(target.Address,".", "_"), strings.ReplaceAll(validRoute.Route, "/", "_"))
			filename := "/app/cameradar/screenshots/" + file
			url :="rtsp://"+target.Username+":"+target.Password+"@"+target.Address+"/"+validRoute.Route
			cmd := exec.Command("ffmpeg", "-loglevel", "fatal", "-i", url, "-vframes", "1", "-r", "1", filename)
			err := cmd.Run()
			fmt.Println(url)
			fmt.Println(cmd)
			if err != nil {
				//log.Fatalf("cmd.Run() failed with %s\n", err)
				fmt.Println("cmd.Run() failed with %s\n", err)
				file = "error"
			} else {
				fmt.Println("Successfully captured screenshot, filename "+filename)
			}

			fmt.Println(target)
			target.ValidRoutes[i].ImageURL = file

		}

	}

	resChan <- target
}
