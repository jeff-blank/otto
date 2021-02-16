package main

import (
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	re "regexp"
	s "strings"

	nc "github.com/Juniper/go-netconf/netconf"
	nrgo "github.com/newrelic/go-agent/v3/newrelic"
	log "github.com/sirupsen/logrus"
)

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

func ncClient(router RouterConfig) (*nc.Session, error) {
	key, err := ioutil.ReadFile(router.SshKeyFile)

	if err != nil {
		log.Fatalf("%s: can't open: %v", router.SshKeyFile, err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.Fatalf("%s: can't parse: %v", router.SshKeyFile, err)
	}

	sshConfig := &ssh.ClientConfig{
		User:            router.Username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	sess, err := nc.DialSSH(router.Hostname, sshConfig)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return sess, nil
}

func tunnelBrokerUpdate(tbConfig TunnelBrokerConfig, slackWebHook string) {
	var (
		tx  *nrgo.Transaction
		seg *nrgo.Segment
	)

	if nrApp != nil {
		tx = nrApp.StartTransaction("tunnelBrokerUpdate")
		defer tx.End()

		seg = nrgo.StartSegment(tx, "HTTP GET to update")
	}
	resp, err := http.Get(fmt.Sprintf(tbConfig.UpdateUrl, tbConfig.Username, tbConfig.Password, tbConfig.TunnelId))
	if nrApp != nil {
		seg.End()
	}
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

func routerPubIPUpdate(router RouterConfig, newIP, slackWebHook string) bool {
	var (
		tx  *nrgo.Transaction
		seg *nrgo.Segment
	)

	ncSess, err := ncClient(router)
	if err != nil {
		return false
	}
	defer ncSess.Close()

	if nrApp != nil {
		tx = nrApp.StartTransaction("routerPubIPUpdate")
		defer tx.End()

		seg = nrgo.StartSegment(tx, "Get ip-0/0/0 config")
	}
	ifXML, err := ncSess.Exec(nc.RawMethod(jGetConfig("running", "<interfaces><interface>ip-0/0/0</interface></interfaces>")))
	if nrApp != nil {
		seg.End()
	}
	if err != nil {
		printAddLogEnt(fmt.Sprintf("NetConf exec(get-config) failed: %v", err), "Fatal", slackWebHook)
	}

	if nrApp != nil {
		seg = nrgo.StartSegment(tx, "Update ip-0/0/0 tunnel source(s)")
	}
	updateXML := globalRegex["tunnelSource"].ReplaceAllString(ifXML.Data, "${1}"+newIP)
	if nrApp != nil {
		seg.End()
	}

	if nrApp != nil {
		seg = nrgo.StartSegment(tx, "Lock router configuration")
	}
	_, err = ncSess.Exec(nc.MethodLock("candidate"))
	if nrApp != nil {
		seg.End()
	}
	if err != nil {
		printAddLogEnt(fmt.Sprintf("NetConf exec(lock) failed: %v", err), "Error", slackWebHook)
		// sleep
		return false
	}

	if nrApp != nil {
		seg = nrgo.StartSegment(tx, "Send ip-0/0/0 config update")
	}
	_, err = ncSess.Exec(nc.RawMethod(jSetConfig("candidate", updateXML)))
	if nrApp != nil {
		seg.End()
	}
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

	if nrApp != nil {
		seg = nrgo.StartSegment(tx, "Commit router configuration")
	}
	_, err = ncSess.Exec(nc.RawMethod("<commit/>"))
	if nrApp != nil {
		seg.End()
	}
	if err != nil {
		printAddLogEnt(fmt.Sprintf("NetConf exec(commit) failed: %v", err), "Error", slackWebHook)
		_, err = ncSess.Exec(nc.MethodUnlock("candidate"))
		if err != nil {
			printAddLogEnt(fmt.Sprintf("NetConf exec(unlock) failed: %v", err), "Error", slackWebHook)
		}
		return false
	}

	if nrApp != nil {
		seg = nrgo.StartSegment(tx, "Unlock router configuration")
	}
	_, err = ncSess.Exec(nc.MethodUnlock("candidate"))
	if nrApp != nil {
		seg.End()
	}
	if err != nil {
		printAddLogEnt(fmt.Sprintf("NetConf exec(unlock) failed: %v", err), "Error", slackWebHook)
		// sleep
		return false
	}
	return true
}

func logSlack(webHookURL string) {
	var (
		tx  *nrgo.Transaction
		seg *nrgo.Segment
	)
	if nrApp != nil {
		tx = nrApp.StartTransaction("logSlack")
		defer tx.End()
	}
	slackPayload := `{"attachments":[`
	slackPayloadFmt := `{"fallback":"New Changes/Errors","color":"%s","pretext":"New Changes/Errors","fields":[{"title":"%s","value":"%s","short":false}]},`
	for _, logEnt := range logBuf {
		slackPayload += fmt.Sprintf(slackPayloadFmt, LOGLEVEL[logEnt.Level], logEnt.Level, logEnt.Message)
	}
	slackPayload += "]}"
	log.Debugf("%#v", slackPayload)
	if nrApp != nil {
		seg = nrgo.StartSegment(tx, "Slack HTTP POST")
	}
	// TODO: check the results of the POST
	resp, _ := http.PostForm(webHookURL, url.Values{"payload": []string{slackPayload}})
	if nrApp != nil {
		seg.End()
	}
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
	switch level {
	case "Error":
		log.Error(msg)
	case "Warning":
		log.Warn(msg)
	case "Debug":
		log.Debug(msg)
	default:
		log.Info(msg)
	}
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

func init() {
	var err error

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
}
