package main

import (
	"fmt"
	"os"
	"strings"
	"time"
	"net"

	"github.com/Ullaakut/cameradar"
	"github.com/Ullaakut/disgo"
	"github.com/Ullaakut/disgo/style"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)


// IP4V addresses don't usually have semicolons, not the best solution but works
func IsIpv4Net(address string) bool {
   return strings.Count(address, ":") < 2
}

func getLocalNetworks() []string {
	var networks []string
	netInterfaces, err := net.InterfaceAddrs()
	// remove all IPv6 and localhost
	if err == nil {
		for _, netInterface := range netInterfaces {	
				addr := strings.Split(netInterface.String(), "/")[0]
				if IsIpv4Net(addr) && strings.Contains(addr, "192.168.") {
					networks = append(networks, netInterface.String())
				}
		}
	}
   return networks
}

func parseArguments() error {

	viper.SetEnvPrefix("cameradar")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	pflag.StringSliceP("targets", "t", []string{},"The targets on which to scan for open RTSP streams - required (ex: 172.16.100.0/24)")
	pflag.StringSliceP("ports", "p", []string{"554", "5554", "8554"}, "The ports on which to search for RTSP streams")
	pflag.StringP("custom-routes", "r", "${GOPATH}/src/github.com/Ullaakut/cameradar/dictionaries/routes", "The path on which to load a custom routes dictionary")
	pflag.IntP("scan-speed", "s", 4, "The nmap speed preset to use for scanning (lower is stealthier)")
	pflag.DurationP("attack-interval", "I", 0, "The interval between each attack  (i.e: 2000ms, higher is stealthier)")
	pflag.DurationP("timeout", "T", 2000*time.Millisecond, "The timeout to use for attack attempts (i.e: 2000ms)")
	pflag.BoolP("debug", "d", true, "Enable the debug logs")
	pflag.BoolP("verbose", "v", false, "Enable the verbose logs")
	pflag.BoolP("help", "h", false, "displays this help message")

	pflag.StringP("username", "u", "admin", "Username for the camera")
	pflag.StringP("password", "P", "", "Password for the camera")
	viper.AutomaticEnv()

	pflag.Parse()

	err := viper.BindPFlags(pflag.CommandLine)
	if err != nil {
		return err
	}

	if viper.GetBool("help") {
		pflag.Usage()
		fmt.Println("\nExamples of usage:")
		fmt.Println("\tScanning your home network for RTSP streams:\tcameradar -t 192.168.0.0/24")
		fmt.Println("\tScanning a remote camera on a specific port:\tcameradar -t 172.178.10.14 -p 18554 -s 2")
		fmt.Println("\tScanning an unstable remote network: \t\tcameradar -t 172.178.10.14/24 -s 1 --timeout 10000 -l")
		fmt.Println("\tStealthily scanning a remote network: \t\tcameradar -t 172.178.10.14/24 -s 1 -I 5000")
		os.Exit(0)
	}

	targets := viper.GetStringSlice("targets")
	if len(targets) == 0 {
		fmt.Println("\nNo targets provided. Detecting networks.. automatically.")
		auto_networks := getLocalNetworks()
		fmt.Println("\nThe following range(s) will be scanned: ")
		fmt.Println(auto_networks)
		targets = auto_networks
	}
    viper.Set("targets", targets)

	if viper.GetString("password") == "" {
		fmt.Println("\nTNo password was provided. Empty password will be used.")
	}

	return nil
}

func main() {
	err := parseArguments()
	if err != nil {
		printErr(err)
	}

	c, err := cameradar.New(
		cameradar.WithTargets(viper.GetStringSlice("targets")),
		cameradar.WithPorts(viper.GetStringSlice("ports")),
		cameradar.WithDebug(viper.GetBool("debug")),
		cameradar.WithVerbose(viper.GetBool("verbose")),
		cameradar.WithCustomRoutes(viper.GetString("custom-routes")),
		cameradar.WithScanSpeed(viper.GetInt("scan-speed")),
		cameradar.WithAttackInterval(viper.GetDuration("attack-interval")),
		cameradar.WithTimeout(viper.GetDuration("timeout")),
		cameradar.WithUsername(viper.GetString("username")),
		cameradar.WithPassword(viper.GetString("password")),
	)
	if err != nil {
		printErr(err)
	}

	scanResult, err := c.Scan()
	if err != nil {
		printErr(err)
	}

	streams, err := c.Attack(scanResult)
	if err != nil {
		printErr(err)
	}

	c.PrintStreams(streams)
}

func printErr(err error) {
	disgo.Errorln(style.Failure(style.SymbolCross), err)
	os.Exit(1)
}
