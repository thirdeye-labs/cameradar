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

// Attack attacks the given targets and returns the accessed streams.
func (s *Scanner) Attack(targets []Stream) ([]Stream, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("unable to attack empty list of targets")
	}

	// Most cameras will be accessed successfully with these two attacks.
	s.term.StartStepf("Attacking routes of %d streams", len(targets))
	streams := s.AttackRoute(targets)

	s.term.StartStepf("Attempting to detect authentication methods of %d streams", len(targets))
	streams = s.DetectAuthMethods(streams)

	s.term.StartStepf("Attacking credentials of %d streams", len(targets))
	streams = s.AttackCredentials(streams)

	s.term.StartStep("Validating that streams are accessible")
	streams = s.ValidateStreams(streams)

	// But some cameras run GST RTSP Server which prioritizes 401 over 404 contrary to most cameras.
	// For these cameras, running another route attack will solve the problem.
	for _, stream := range streams {
		if len(stream.ValidRoutes) == 0 	{
			s.term.StartStepf("Second round of attacks")
			streams = s.AttackRoute(streams)

			s.term.StartStep("Validating that streams are accessible")
			streams = s.ValidateStreams(streams)

			break
		}
	}

	s.term.EndStep()

	return streams, nil
}

// ValidateStreams tries to setup the stream to validate whether or not it is available.
func (s *Scanner) ValidateStreams(targets []Stream) []Stream {
	for i, target := range targets {
		for c, route := range target.ValidRoutes	{
			targets[i].ValidRoutes[c].Available = s.validateStream(targets[i], route.Route)
			time.Sleep(s.attackInterval)
		}
	}

	return targets
}

// AttackCredentials attempts to guess the provided targets' credentials using the given
// dictionary or the default dictionary if none was provided by the user.
func (s *Scanner) AttackCredentials(targets []Stream) []Stream {
	resChan := make(chan Stream)
	defer close(resChan)

	for _, target := range targets {
		// TODO: Perf Improvement: Skip cameras with no auth type detected, and set their
		// CredentialsFound value to true.
		go s.attackCameraCredentials(target, resChan)
	}

	attackResults := []Stream{}
	// TODO: Change this into a for+select and make a successful result close the chan.
	for range targets {
		attackResults = append(attackResults, <-resChan)
	}

	return attackResults
}

// AttackRoute attempts to guess the provided targets' streaming routes using the given
// dictionary or the default dictionary if none was provided by the user.
func (s *Scanner) AttackRoute(targets []Stream) []Stream {
	resChan := make(chan Stream)
	defer close(resChan)

	for i := range targets {
		go s.attackCameraRoute(targets[i], resChan)
	}

	attackResults := []Stream{}
	// TODO: Change this into a for+select and make a successful result close the chan.
	for range targets {
		attackResults = append(attackResults, <-resChan)
	}

	for i := range attackResults {
		if len(attackResults[i].ValidRoutes) > 0 {
			targets = replace(targets, attackResults[i])
		}
	}
	return targets
}

// DetectAuthMethods attempts to guess the provided targets' authentication types, between
// digest, basic auth or none at all.
func (s *Scanner) DetectAuthMethods(targets []Stream) []Stream {
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

		s.term.Debugf("Stream %s uses %s authentication method\n", GetCameraRTSPURL(targets[i]), authMethod)
	}

	return targets
}

func (s *Scanner) attackCameraCredentials(target Stream, resChan chan<- Stream) {
	for i, route := range target.ValidRoutes{
		ok := s.credAttack(target, s.username, s.password, route.Route)
		if ok {
			route.CredentialsFound = true
			target.Username = s.username
			target.Password = s.password
		} else {
			route.CredentialsFound = false
		}
		target.ValidRoutes[i] = route
		time.Sleep(s.attackInterval)
	}
	resChan <- target
}

func (s *Scanner) attackCameraRoute(target Stream, resChan chan<- Stream) {
	var v ValidRoute

	for _, route := range s.routes {
		ok := s.routeAttack(target, route)
		if ok {
			// Route=route, credentials_found=false, available=false
			v.Route = route
			v.CredentialsFound = false
			v.Available = false

			target.ValidRoutes = append(target.ValidRoutes, v)
		}
		time.Sleep(s.attackInterval)
	}

	resChan <- target
}

func (s *Scanner) detectAuthMethod(stream Stream) int {
	c := s.curl.Duphandle()

	// Will only scan the first valid route of the device
	route := ""
	if len(stream.ValidRoutes) > 0{
		route = stream.ValidRoutes[0].Route
	}

	attackURL := fmt.Sprintf(
		"rtsp://%s:%d/%s",
		stream.Address,
		stream.Port,
		route, 
	)

	s.setCurlOptions(c)

	// Send a request to the URL of the stream we want to attack.
	_ = c.Setopt(curl.OPT_URL, attackURL)
	// Set the RTSP STREAM URI as the stream URL.
	_ = c.Setopt(curl.OPT_RTSP_STREAM_URI, attackURL)
	_ = c.Setopt(curl.OPT_RTSP_REQUEST, rtspDescribe)

	// Perform the request.
	err := c.Perform()
	if err != nil {
		s.term.Errorf("Perform failed for %q (auth %d): %v", attackURL, stream.AuthenticationType, err)
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

func (s *Scanner) routeAttack(stream Stream, route string) bool {
	c := s.curl.Duphandle()

	attackURL := fmt.Sprintf(
		"rtsp://%s:%s@%s:%d/%s",
		stream.Username,
		stream.Password,
		stream.Address,
		stream.Port,
		route,
	)

	s.setCurlOptions(c)

	// Set proper authentication type.
	_ = c.Setopt(curl.OPT_HTTPAUTH, stream.AuthenticationType)
	_ = c.Setopt(curl.OPT_USERPWD, fmt.Sprint(stream.Username, ":", stream.Password))

	// Send a request to the URL of the stream we want to attack.
	_ = c.Setopt(curl.OPT_URL, attackURL)
	// Set the RTSP STREAM URI as the stream URL.
	_ = c.Setopt(curl.OPT_RTSP_STREAM_URI, attackURL)
	_ = c.Setopt(curl.OPT_RTSP_REQUEST, rtspDescribe)

	// Perform the request.
	err := c.Perform()
	if err != nil {
		s.term.Errorf("Perform failed for %q (auth %d): %v", attackURL, stream.AuthenticationType, err)
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
	// If it's a 401 or 403, it means that the credentials are wrong but the route might be okay.
	// If it's a 200, the stream is accessed successfully.
	if rc == httpOK || rc == httpUnauthorized || rc == httpForbidden {
		return true
	}
	return false
}

func (s *Scanner) credAttack(stream Stream, username string, password string, route string) bool {
	c := s.curl.Duphandle()

	attackURL := fmt.Sprintf(
		"rtsp://%s:%s@%s:%d/%s",
		username,
		password,
		stream.Address,
		stream.Port,
		route, 
	)

	s.setCurlOptions(c)

	// Set proper authentication type.
	_ = c.Setopt(curl.OPT_HTTPAUTH, stream.AuthenticationType)
	_ = c.Setopt(curl.OPT_USERPWD, fmt.Sprint(username, ":", password))

	// Send a request to the URL of the stream we want to attack.
	_ = c.Setopt(curl.OPT_URL, attackURL)
	// Set the RTSP STREAM URI as the stream URL.
	_ = c.Setopt(curl.OPT_RTSP_STREAM_URI, attackURL)
	_ = c.Setopt(curl.OPT_RTSP_REQUEST, rtspDescribe)

	// Perform the request.
	err := c.Perform()
	if err != nil {
		s.term.Errorf("Perform failed for %q (auth %d): %v", attackURL, stream.AuthenticationType, err)
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

	// If it's a 404, it means that the route is incorrect but the credentials might be okay.
	// If it's a 200, the stream is accessed successfully.
	if rc == httpOK || rc == httpNotFound {
		return true
	}
	return false
}

func (s *Scanner) validateStream(stream Stream, route string) bool {
	c := s.curl.Duphandle()

	attackURL := fmt.Sprintf(
		"rtsp://%s:%s@%s:%d/%s",
		stream.Username,
		stream.Password,
		stream.Address,
		stream.Port,
		route,
	)

	s.setCurlOptions(c)

	// Set proper authentication type.
	_ = c.Setopt(curl.OPT_HTTPAUTH, stream.AuthenticationType)
	_ = c.Setopt(curl.OPT_USERPWD, fmt.Sprint(stream.Username, ":", stream.Password))

	// Send a request to the URL of the stream we want to attack.
	_ = c.Setopt(curl.OPT_URL, attackURL)
	// Set the RTSP STREAM URI as the stream URL.
	_ = c.Setopt(curl.OPT_RTSP_STREAM_URI, attackURL)
	_ = c.Setopt(curl.OPT_RTSP_REQUEST, rtspSetup)

	_ = c.Setopt(curl.OPT_RTSP_TRANSPORT, "RTP/AVP;unicast;client_port=33332-33333")

	// Perform the request.
	err := c.Perform()
	if err != nil {
		s.term.Errorf("Perform failed for %q (auth %d): %v", attackURL, stream.AuthenticationType, err)
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
	// If it's a 200, the stream is accessed successfully.
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
