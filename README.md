# otto


### Junos SNMP v3 configuration example

    set snmp v3 usm local-engine user public authentication-sha authentication-key "$9..."
    set snmp v3 usm local-engine user public privacy-aes128 privacy-key "$9..."
    set snmp v3 vacm security-to-group security-model usm security-name public group public
    set snmp v3 vacm access group public default-context-prefix security-model usm security-level privacy read-view interfaces
    set snmp engine-id use-mac-address
    set snmp view interfaces oid 1.3.6.1.2.1.2 include
    set snmp view interfaces oid 1.3.6.1.2.1.4.20.1.2 include
    set snmp community public authorization read-only
    set snmp community public clients 192.168.10.1/24
    set snmp community public clients fc10::/64

