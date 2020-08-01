package main

import (
	"fmt"
	sc "strconv"
	s "strings"
	"time"

	nrgo "github.com/newrelic/go-agent/v3/newrelic"
	log "github.com/sirupsen/logrus"
	snmp "github.com/soniah/gosnmp"
)

func SNMPSess(config Config) *snmp.GoSNMP {
	var snmpCfg *snmp.GoSNMP
	if config.Snmp.Version == "3" {
		snmpCfg = &snmp.GoSNMP{
			Target:        config.Router.Hostname,
			Port:          config.Snmp.Port,
			Version:       snmp.Version3,
			Timeout:       time.Duration(config.Snmp.Timeout) * time.Second,
			SecurityModel: snmp.UserSecurityModel, // TODO?
			MsgFlags:      snmp.AuthPriv,          // TODO
			SecurityParameters: &snmp.UsmSecurityParameters{
				UserName:                 config.Snmp.V3.Username,
				AuthenticationProtocol:   snmp.SHA, // TODO
				AuthenticationPassphrase: config.Snmp.V3.AuthPass,
				PrivacyProtocol:          snmp.AES, // TODO
				PrivacyPassphrase:        config.Snmp.V3.PrivPass,
			},
		}
	} else {
		log.Fatalf("Unsupported SNMP version '%s'", config.Snmp.Version)
	}

	err := snmpCfg.Connect()
	if err != nil {
		log.Fatalf("SNMP connect: %v", err)
	}
	return snmpCfg
}

func getPubIP(config Config, sess *snmp.GoSNMP) string {
	var (
		tx  *nrgo.Transaction
		seg *nrgo.Segment
	)
	pollSecondsErr := config.Router.IpPollSecondsErr
	pubIfIndex := -1

	if nrApp != nil {
		tx = nrApp.StartTransaction("getPubIP")
		defer tx.End()

		// we'll do this every poll interval in case the router is a Juniper
		// and it gets upgraded or is otherwise rebooted
		seg = nrgo.StartSegment(tx, "BulkWalkAll ifDescr")
	}
	res, err := sess.BulkWalkAll(IF_DESCR)
	if nrApp != nil {
		seg.End()
	}
	if err != nil {
		// non-fatal error; wait extra time before next poll
		printAddLogEnt(fmt.Sprintf("BulkWalkAll %s ifDescr: %v", config.Router.Hostname, err), "Error", config.SlackWebHook)
		if pollSecondsErr > 0 {
			time.Sleep(time.Duration(pollSecondsErr) * time.Second)
			return ""
		}
	}

	if nrApp != nil {
		seg = nrgo.StartSegment(tx, "find ifIndex of public interface")
	}
	for _, pdu := range res {
		if pdu.Type == snmp.OctetString {
			if string(pdu.Value.([]byte)) == config.Router.PubInterface {
				lastDot := s.LastIndexByte(pdu.Name, '.')
				if lastDot == -1 {
					if nrApp != nil {
						seg.End()
					}
					printAddLogEnt(fmt.Sprintf("%s: no dots in OID '%s'", config.Router.Hostname, pdu.Name), "Error", config.SlackWebHook)
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
	if nrApp != nil {
		seg.End()
	}
	if pubIfIndex == -1 {
		printAddLogEnt(fmt.Sprintf("Could not find ifIndex for interface '%s'", config.Router.PubInterface), "Fatal", config.SlackWebHook)
	}

	if nrApp != nil {
		seg = nrgo.StartSegment(tx, "BulkWalkAll ipAdEntIfIndex")
	}
	res, err = sess.BulkWalkAll(IP_AD_ENT_IF_INDEX)
	if nrApp != nil {
		seg.End()
	}
	if err != nil {
		errMsg := fmt.Sprintf("BulkWalkAll ipAdEntIfIndex: %v", err)
		logBuf = append(logBuf, LogEnt{Message: errMsg, Level: "Fatal"})
		logSlack(config.SlackWebHook)
		log.Fatal(errMsg)
	}

	if nrApp != nil {
		seg = nrgo.StartSegment(tx, "find public IP")
	}
	for _, pdu := range res {
		if pdu.Type == snmp.Integer && pdu.Value.(int) == pubIfIndex {
			if nrApp != nil {
				seg.End()
			}
			return pdu.Name[len(IP_AD_ENT_IF_INDEX)+1:]
		}
	}
	if nrApp != nil {
		seg.End()
	}

	return "N/A"
}
