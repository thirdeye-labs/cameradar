package cameradar

import (
	"strings"

	"github.com/Ullaakut/nmap"
)

// Scan scans the target networks and tries to find RTSP devices within them.
//
// targets can be:
//
//    - a subnet (e.g.: 172.16.100.0/24)
//    - an IP (e.g.: 172.16.100.10)
//    - a hostname (e.g.: localhost)
//    - a range of IPs (e.g.: 172.16.100.10-20)
//
// ports can be:
//
//    - one or multiple ports and port ranges separated by commas (e.g.: 554,8554-8560,18554-28554)
func (s *Scanner) Scan() ([]Device, error) {
	s.term.StartStep("Scanning the network")

	// Run nmap command to discover open ports on the specified targets & ports.
	nmapScanner, err := nmap.NewScanner(
		nmap.WithTargets(s.targets...),
		nmap.WithPorts(s.ports...),
		nmap.WithTimingTemplate(nmap.Timing(s.scanSpeed)),
	)
	if err != nil {
		return nil, s.term.FailStepf("unable to create network scanner: %v", err)
	}

	return s.scan(nmapScanner)
}

func (s *Scanner) scan(nmapScanner nmap.ScanRunner) ([]Device, error) {
	results, warnings, err := nmapScanner.Run()
	if err != nil {
		return nil, s.term.FailStepf("error while scanning network: %v", err)
	}

	for _, warning := range warnings {
		s.term.Infoln("[Nmap Warning]", warning)
	}

	// Get devices from nmap results.
	var devices []Device
	for _, host := range results.Hosts {
		for _, port := range host.Ports {
			if port.Status() != "open" {
				continue
			}

			if !strings.Contains(port.Service.Name, "rtsp") {
				continue
			}

			for _, address := range host.Addresses {
				devices = append(devices, Device{
					Device:  port.Service.Product,
					Address: address.Addr,
					Port:    port.ID,
				})
			}
		}
	}

	s.term.Debugf("Found %d RTSP devices\n", len(devices))

	s.term.EndStep()

	return devices, nil
}
