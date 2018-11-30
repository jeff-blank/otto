package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	re "regexp"
	sc "strconv"
	s "strings"
	"time"

	nc "github.com/Juniper/go-netconf/netconf"
	nrgo "github.com/newrelic/go-agent"
	log "github.com/sirupsen/logrus"
	snmp "github.com/soniah/gosnmp"
	"gopkg.in/yaml.v2"
)

// constants
const (
	ifDescr        = ".1.3.6.1.2.1.2.2.1.2"
	ipAdEntIfIndex = ".1.3.6.1.2.1.4.20.1.2"
)

var LOGLEVEL = map[string]string{
	"Fatal":   "#000000",
	"Error":   "#ff0000",
	"Warning": "#ffa500",
	"Notice":  "#00ffff",
	"Info":    "#00d000",
	"Debug":   "#0000ff",
}

var globalRegex map[string]*re.Regexp
var logBuf []LogEnt
var pollSeconds int
var nrApp nrgo.Application

type LogEnt struct {
	Message string
	Level   string
}

type SNMPConfig struct {
	Port           uint16            `yaml:"port"`
	Timeout        int               `yaml:"timeoutSecs"`
	Version        string            `yaml:"version"`
	V1V2cCommunity string            `yaml:"v1v2cCommunity"`
	V3             map[string]string `yaml:"v3usm"`
}

type Config struct {
	NRLicense    string            `yaml:"nrLicense"`
	NRAppName    string            `yaml:"nrAppName"`
	StateFile    string            `yaml:"stateFile"`
	PidFile      string            `yaml:"pidFile"`
	Router       map[string]string `yaml:"router"`
	SNMP         SNMPConfig        `yaml:"snmp"`
	TunnelBroker map[string]string `yaml:"tunnelbroker"`
	SlackWebHook string            `yaml:"slackWebHook"`
}

type State struct {
	PubIP      string            `json:"pubIP"`
	ProxyState map[string]string `json:"proxyState"`
}

func SNMPSess(config Config) *snmp.GoSNMP {
	var snmpCfg *snmp.GoSNMP
	if config.SNMP.Version == "3" {
		snmpCfg = &snmp.GoSNMP{
			Target:        config.Router["hostname"],
			Port:          config.SNMP.Port,
			Version:       snmp.Version3,
			Timeout:       time.Duration(config.SNMP.Timeout) * time.Second,
			SecurityModel: snmp.UserSecurityModel, // TODO?
			MsgFlags:      snmp.AuthPriv,          // TODO
			SecurityParameters: &snmp.UsmSecurityParameters{
				UserName:                 config.SNMP.V3["username"],
				AuthenticationProtocol:   snmp.SHA, // TODO
				AuthenticationPassphrase: config.SNMP.V3["authPass"],
				PrivacyProtocol:          snmp.AES, // TODO
				PrivacyPassphrase:        config.SNMP.V3["privPass"],
			},
		}
	} else {
		log.Fatalf("Unsupported SNMP version '%s'", config.SNMP.Version)
	}

	err := snmpCfg.Connect()
	if err != nil {
		log.Fatalf("SNMP connect: %v", err)
	}
	return snmpCfg
}

func getPubIP(config Config, sess *snmp.GoSNMP) string {
	pollSecondsErr, _ := sc.Atoi(config.Router["ipPollSecondsErr"])
	pubIfIndex := -1

	tx := nrApp.StartTransaction("getPubIP", nil, nil)
	defer tx.End()

	// we'll do this every poll interval in case the router is a Juniper
	// and it gets upgraded or is otherwise rebooted
	seg := nrgo.StartSegment(tx, "BulkWalkAll ifDescr")
	res, err := sess.BulkWalkAll(ifDescr)
	seg.End()
	if err != nil {
		// non-fatal error; wait extra time before next poll
		printAddLogEnt(fmt.Sprintf("BulkWalkAll %s ifDescr: %v", config.Router["hostname"], err), "Error", config.SlackWebHook)
		if pollSecondsErr > 0 {
			time.Sleep(time.Duration(pollSecondsErr) * time.Second)
			return ""
		}
	}

	seg = nrgo.StartSegment(tx, "find ifIndex of public interface")
	for _, pdu := range res {
		if pdu.Type == snmp.OctetString {
			if string(pdu.Value.([]byte)) == config.Router["pubInterface"] {
				lastDot := s.LastIndexByte(pdu.Name, '.')
				if lastDot == -1 {
					seg.End()
					printAddLogEnt(fmt.Sprintf("%s: no dots in OID '%s'", config.Router["hostname"], pdu.Name), "Error", config.SlackWebHook)
					if pollSecondsErr > 0 {
						time.Sleep(time.Duration(pollSecondsErr) * time.Second)
						return ""
					}
				}
				pubIfIndex, err = sc.Atoi(pdu.Name[lastDot+1:])
				break
			}
		}
	}
	seg.End()
	if pubIfIndex == -1 {
		printAddLogEnt(fmt.Sprintf("Could not find ifIndex for interface '%s'", config.Router["pubInterface"]), "Fatal", config.SlackWebHook)
	}

	seg = nrgo.StartSegment(tx, "BulkWalkAll ipAdEntIfIndex")
	res, err = sess.BulkWalkAll(ipAdEntIfIndex)
	seg.End()
	if err != nil {
		errMsg := fmt.Sprintf("BulkWalkAll ipAdEntIfIndex: %v", err)
		logBuf = append(logBuf, LogEnt{Message: errMsg, Level: "Fatal"})
		logSlack(config.SlackWebHook)
		log.Fatal(errMsg)
	}

	seg = nrgo.StartSegment(tx, "find public IP")
	for _, pdu := range res {
		if pdu.Type == snmp.Integer && pdu.Value.(int) == pubIfIndex {
			seg.End()
			return pdu.Name[len(ipAdEntIfIndex)+1:]
		}
	}

	seg.End()
	return "N/A"
}

func getLastState(stateFile string) State {
	var state State
	stateJSON, err := ioutil.ReadFile(stateFile)
	if err != nil {
		log.Fatalf("Can't open state file %s: %v", stateFile, err)
	}
	err = json.Unmarshal(stateJSON, &state)
	if err != nil {
		log.Fatalf("Can't unmarshal state file %s: %v", stateFile, err)
	}
	return state
}

func writeState(stateFile string, state State) {
	jsonState, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		errMsg := fmt.Sprintf("Can't marshal current state to JSON: %v", err)
		logBuf = append(logBuf, LogEnt{Message: errMsg, Level: "Error"})
		log.Print(errMsg)
		return
	}
	err = ioutil.WriteFile(stateFile, jsonState, 0600)
	if err != nil {
		errMsg := fmt.Sprintf("Error writing state to %s: %v", stateFile, err)
		logBuf = append(logBuf, LogEnt{Message: errMsg, Level: "Error"})
		log.Print(errMsg)
	}
}

func ncClient(router map[string]string) *nc.Session {
	key, err := ioutil.ReadFile(router["sshKeyFile"])

	if err != nil {
		log.Fatalf("%s: can't open: %v", router["sshKeyFile"], err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.Fatalf("%s: can't parse: %v", router["sshKeyFile"], err)
	}

	sshConfig := &ssh.ClientConfig{
		User:            router["username"],
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	sess, err := nc.DialSSH(router["hostname"], sshConfig)
	if err != nil {
		log.Fatal(err)
	}
	return sess
}

func tunnelBrokerUpdate(tbConfig map[string]string, slackWebHook string) {
	tx := nrApp.StartTransaction("tunnelBrokerUpdate", nil, nil)
	defer tx.End()

	seg := nrgo.StartSegment(tx, "HTTP GET to update")
	resp, err := http.Get(fmt.Sprintf("https://%s:%s@ipv4.tunnelbroker.net/nic/update?hostname=%s", tbConfig["username"], tbConfig["password"], tbConfig["tunnelId"]))
	seg.End()
	defer resp.Body.Close()

	// config.LogActions
	if err == nil {
		printAddLogEnt("Updated IPv4 endpoint registered with IPv6 tunnel broker", "Info", slackWebHook)
	} else {
		printAddLogEnt(fmt.Sprintf("Error updating IPv6 tunnel: %v", err), "Error", slackWebHook)
	}
}

func jGetConfig(source, filter string) string {
	rstr := "<get-config><source><" + source + "/></source>"
	if len(filter) > 0 {
		rstr += fmt.Sprintf("<filter><configuration>%s</configuration></filter>", filter)
	}
	return rstr + "</get-config>"
}

func jSetConfig(target, updateXML string) string {

	updateXML = s.Replace(updateXML, "\n", "{NEWLINE}", -1)
	updateXML = globalRegex["loadConfigFragment"].ReplaceAllString(updateXML, "<config><configuration>$1</configuration></config>")
	updateXML = globalRegex["reNewline"].ReplaceAllString(updateXML, "\n")

	return "<edit-config><default-operation>merge</default-operation><target><" + target + "/></target>" + updateXML + "</edit-config>"
}

func readConfigFile(path string) Config {
	var config Config
	yamlText, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalf("Can't read %s: %v", path, err)
	}
	err = yaml.Unmarshal(yamlText, &config)
	if err != nil {
		log.Fatalf("Can't unmarshal YAML from %s: %v", path, err)
	}

	// TODO: param validation

	return config
}

func routerPubIPUpdate(router map[string]string, newIP, slackWebHook string) bool {
	ncSess := ncClient(router)
	defer ncSess.Close()

	tx := nrApp.StartTransaction("routerPubIPUpdate", nil, nil)
	defer tx.End()

	seg := nrgo.StartSegment(tx, "Get ip-0/0/0 config")
	ifXML, err := ncSess.Exec(nc.RawMethod(jGetConfig("running", "<interfaces><interface>ip-0/0/0</interface></interfaces>")))
	seg.End()
	if err != nil {
		printAddLogEnt(fmt.Sprintf("NetConf exec(get-config) failed: %v", err), "Fatal", slackWebHook)
	}

	seg = nrgo.StartSegment(tx, "Update ip-0/0/0 tunnel source(s)")
	updateXML := globalRegex["tunnelSource"].ReplaceAllString(ifXML.Data, "${1}"+newIP)
	seg.End()

	seg = nrgo.StartSegment(tx, "Lock router configuration")
	_, err = ncSess.Exec(nc.MethodLock("candidate"))
	seg.End()
	if err != nil {
		printAddLogEnt(fmt.Sprintf("NetConf exec(lock) failed: %v", err), "Error", slackWebHook)
		// sleep
		return false
	}

	seg = nrgo.StartSegment(tx, "Send ip-0/0/0 config update")
	_, err = ncSess.Exec(nc.RawMethod(jSetConfig("candidate", updateXML)))
	seg.End()
	if err != nil {
		printAddLogEnt(fmt.Sprintf("NetConf exec(edit-config) failed: %v", err), "Error", slackWebHook)
		log.Print(jSetConfig("candidate", updateXML))
		_, err = ncSess.Exec(nc.MethodUnlock("candidate"))
		if err != nil {
			printAddLogEnt(fmt.Sprintf("NetConf exec(unlock) failed: %v", err), "Error", slackWebHook)
		}
		// sleep
		return false
	}

	seg = nrgo.StartSegment(tx, "Commit router configuration")
	_, err = ncSess.Exec(nc.RawMethod("<commit/>"))
	seg.End()
	if err != nil {
		printAddLogEnt(fmt.Sprintf("NetConf exec(commit) failed: %v", err), "Error", slackWebHook)
		_, err = ncSess.Exec(nc.MethodUnlock("candidate"))
		if err != nil {
			printAddLogEnt(fmt.Sprintf("NetConf exec(unlock) failed: %v", err), "Error", slackWebHook)
		}
		return false
	}

	seg = nrgo.StartSegment(tx, "Unlock router configuration")
	_, err = ncSess.Exec(nc.MethodUnlock("candidate"))
	seg.End()
	if err != nil {
		printAddLogEnt(fmt.Sprintf("NetConf exec(unlock) failed: %v", err), "Error", slackWebHook)
		// sleep
		return false
	}
	return true
}

func logSlack(webHookURL string) {
	tx := nrApp.StartTransaction("logSlack", nil, nil)
	defer tx.End()
	slackPayload := `{"attachments":`
	slackPayloadFmt := `[{"fallback":"New Changes/Errors","color":"%s","pretext":"New Changes/Errors","fields":[{"title":"%s","value":"%s","short":false}]}],`
	for _, logEnt := range logBuf {
		slackPayload += fmt.Sprintf(slackPayloadFmt, LOGLEVEL[logEnt.Level], logEnt.Level, logEnt.Message)
	}
	slackPayload += "}"
	//log.Print(slackPayload)
	seg := nrgo.StartSegment(tx, "Slack HTTP POST")
	resp, _ := http.PostForm(webHookURL, url.Values{"payload": []string{slackPayload}})
	seg.End()
	defer resp.Body.Close()
	logBuf = make([]LogEnt, 0)
}

func printAddLogEnt(msg, level, slackWebHook string) {
	logBuf = append(logBuf, LogEnt{Message: msg, Level: level})
	if level == "Fatal" {
		// flush log messages to Slack if using
		if len(slackWebHook) > 0 {
			logSlack(slackWebHook)
		}
		log.Fatal(msg)
	}
	log.Print(msg)
}

func running(path string) bool {
	pidStr, err := ioutil.ReadFile(path)
	if err == nil {
		// pid file exists; read it
		captureLeadingDigits, err := re.Compile(`^(\d+)[\n.]*`)
		if err != nil {
			log.Fatalf("%v", err)
		}

		pidStr = captureLeadingDigits.ReplaceAll(pidStr, []byte(`$1`))
		psCmd := exec.Command("/bin/ps", "cp"+string(pidStr))
		if err != nil {
			log.Fatalf("exec /bin/ps: %v", err)
		}

		psData, err := psCmd.Output()
		if err != nil && err.Error() != "exit status 1" {
			log.Fatalf("read from /bin/ps: %v", err)
		}

		if s.IndexByte(string(psData), '\n') == len(psData)-1 {
			// no process found
			return false
		} else {
			// process found--don't care whether it's a previous instance
			// of this or something completely unrelated
			return true
		}
	} else {
		// error reading pid file; if it doesn't exist, we're good; otherwise bail
		errStr := fmt.Sprintf("%v", err)
		if errStr[len(errStr)-25:] != "no such file or directory" {
			log.Fatalf("%v (%s)", err)
		}
		return false
	}
	return true
}

func createPidFile(path string) {
	err := ioutil.WriteFile(path, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0666)
	if err != nil {
		log.Fatalf("can't create %s: %v", path, err)
	}
}

func main() {
	var err error

	configFile := flag.String("conf", "/usr/local/etc/otto.yml", "configuration file (YAML)")
	verbose := flag.Bool("v", true, "Increase verbosity")
	flag.Parse()

	config := readConfigFile(*configFile)

	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	globalRegex = make(map[string]*re.Regexp)
	globalRegex["rfc1918"], err = re.Compile(`^1(0|72\.(1[6-9]|2[0-9]|3[01])|92\.168)\.`)
	if err != nil {
		log.Fatalf("unable to compile 'rfc1918': %v", err)
	}
	globalRegex["tunnelSource"], err = re.Compile(`(<tunnel.*?>\s+<source>)\d+\.\d+\.\d+\.\d+`)
	if err != nil {
		log.Fatalf("unable to compile 'tunnelSource': %v", err)
	}
	globalRegex["loadConfigFragment"], err = re.Compile(`.*<configuration.*?>(.*)</configuration>.*`)
	if err != nil {
		log.Fatalf("unable to compile 'loadConfigFragment': %v", err)
	}
	globalRegex["reNewline"], err = re.Compile(`{NEWLINE}`)
	if err != nil {
		log.Fatalf("unable to compile 'reNewline': %v", err)
	}
	globalRegex["lessThan"], err = re.Compile(`<`)
	if err != nil {
		log.Fatalf("unable to compile 'reNewline': %v", err)
	}

	nrConfig := nrgo.NewConfig(config.NRAppName, config.NRLicense)
	nrApp, err = nrgo.NewApplication(nrConfig)
	if err != nil {
		log.Fatalf("unable to create New Relic app object: %v\n%v", err, config)
	}

	snmpsess := SNMPSess(config)
	state := getLastState(config.StateFile)

	pollSeconds, err := sc.Atoi(config.Router["ipPollSeconds"])
	if err != nil {
		log.Fatalf("Atoi(poll seconds) failed: %v", err)
	}
	pollTicker := time.NewTicker(time.Duration(pollSeconds) * time.Second)
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
			if pubIP != "N/A" && len(globalRegex["rfc1918"].Find([]byte(pubIP))) == 0 && state.PubIP != pubIP {
				log.Printf("pub IP now '%s'", pubIP)
				success := routerPubIPUpdate(config.Router, pubIP, config.SlackWebHook)
				tunnelBrokerUpdate(config.TunnelBroker, config.SlackWebHook)
				if success {
					printAddLogEnt(fmt.Sprintf("Public IP updated from %s to %s", state.PubIP, pubIP), "Info", config.SlackWebHook)
					state.PubIP = pubIP
					writeState(config.StateFile, state)
				}
			}
			if len(logBuf) > 0 {
				logSlack(config.SlackWebHook)
			}
			<-pollTicker.C
		}
	}()

	for {
		time.Sleep(time.Duration(100) * time.Second)
	}
}
