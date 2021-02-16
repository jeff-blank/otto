package main

import (
	"flag"
	"fmt"
	"net/http"
	re "regexp"
	"time"

	nrgo "github.com/newrelic/go-agent/v3/newrelic"
	log "github.com/sirupsen/logrus"
)

// constants
const (
	IF_DESCR           = ".1.3.6.1.2.1.2.2.1.2"
	IP_AD_ENT_IF_INDEX = ".1.3.6.1.2.1.4.20.1.2"
)

var LOGLEVEL = map[string]string{
	"Fatal":   "#000000",
	"Error":   "#ff0000",
	"Warning": "#ffa500",
	"Notice":  "#00ffff",
	"Info":    "#00d000",
	"Debug":   "#0000ff",
}

var (
	globalRegex map[string]*re.Regexp
	logBuf      []LogEnt
	nrApp       *nrgo.Application
)

type LogEnt struct {
	Message string
	Level   string
}

type SnmpV3UsmConfig struct {
	Username      string `yaml:"username"`
	AuthType      string `yaml:"auth_type"`
	AuthPass      string `yaml:"auth_pass"`
	PrivType      string `yaml:"priv_type"`
	PrivPass      string `yaml:"priv_pass"`
	SecurityLevel string `yaml:"security_level"`
}

type SnmpConfig struct {
	Port           uint16          `yaml:"port"`
	Timeout        int             `yaml:"timeout_secs"`
	Version        string          `yaml:"version"`
	V1V2cCommunity string          `yaml:"v1_v2_community"`
	V3             SnmpV3UsmConfig `yaml:"v3_usm"`
}

type RouterConfig struct {
	IpPollSeconds    int    `yaml:"ip_poll_seconds"`
	IpPollSecondsErr int    `yaml:"ip_poll_seconds_err"`
	Hostname         string `yaml:"hostname"`
	Username         string `yaml:"username"`
	SshKeyFile       string `yaml:"ssh_key_file"`
	PubInterface     string `yaml:"pub_interface"`
}

type TunnelBrokerConfig struct {
	Username  string `yaml:"username"`
	Password  string `yaml:"password"`
	TunnelId  string `yaml:"tunnel_id"`
	UpdateUrl string `yaml:"update_url"`
}

type Config struct {
	NrLicense    string             `yaml:"nr_license"`
	NrAppName    string             `yaml:"nr_app_name"`
	StateFile    string             `yaml:"state_file"`
	PidFile      string             `yaml:"pid_file"`
	Router       RouterConfig       `yaml:"router"`
	Snmp         SnmpConfig         `yaml:"snmp"`
	TunnelBroker TunnelBrokerConfig `yaml:"tunnelbroker"`
	SlackWebHook string             `yaml:"slack_web_hook"`
	HttpBind     string             `yaml:"http_bind"`
}

type State struct {
	PubIp      string            `json:"pub_IP"`
	ProxyState map[string]string `json:"proxy_state"`
}

func main() {
	var err error

	configFile := flag.String("conf", "/usr/local/etc/otto.yml", "configuration file (YAML)")
	verbose := flag.Bool("v", false, "Increase verbosity")
	flag.Parse()

	config := readConfigFile(*configFile)

	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	if config.NrLicense != "" {
		nrApp, err = nrgo.NewApplication(
			nrgo.ConfigAppName(config.NrAppName),
			nrgo.ConfigLicense(config.NrLicense),
		)
		if err != nil {
			log.Fatalf("unable to create New Relic app object: %v\n%v", err, config)
		}
	}

	snmpsess := SNMPSess(config)
	state := getLastState(config.StateFile)

	ipPollSeconds := config.Router.IpPollSeconds

	pollTicker := time.NewTicker(time.Duration(ipPollSeconds) * time.Second)
	defer pollTicker.Stop()

	if running(config.PidFile) {
		log.Fatal("a running instance of this program was detected.")
	} else {
		// now that we're actually running (past all the log.Fatal[f]() calls),
		// time to create a pid file
		createPidFile(config.PidFile)
	}

	go func() {
		for {
			pubIP := getPubIP(config, snmpsess)
			if pubIP != "N/A" && len(globalRegex["rfc1918"].Find([]byte(pubIP))) == 0 && state.PubIp != pubIP {
				log.Infof("pub IP now '%s'", pubIP)
				success := routerPubIPUpdate(config.Router, pubIP, config.SlackWebHook)
				tunnelBrokerUpdate(config.TunnelBroker, config.SlackWebHook)
				if success {
					printAddLogEnt(fmt.Sprintf("Public IP updated from %s to %s", state.PubIp, pubIP), "Info", config.SlackWebHook)
					state.PubIp = pubIP
					writeState(config.StateFile, state)
				}
			}
			if len(logBuf) > 0 {
				logSlack(config.SlackWebHook)
			}
			<-pollTicker.C
		}
	}()

	if nrApp == nil {
		http.HandleFunc("/status/check", statusCheck)
		http.HandleFunc("/status/info", statusInfo)
	} else {
		http.HandleFunc(nrgo.WrapHandleFunc(nrApp, "/status/check", statusCheck))
		http.HandleFunc(nrgo.WrapHandleFunc(nrApp, "/status/info", statusInfo))
	}
	log.Fatal(http.ListenAndServe(config.HttpBind, nil))

}
