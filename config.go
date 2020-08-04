package main

import (
	"io/ioutil"
	"log"
	"os"

	"gopkg.in/yaml.v2"
)

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

	// overrides from environment

	if url, found := os.LookupEnv("SLACK_WEB_HOOK"); found {
		config.SlackWebHook = url
	}

	if license, found := os.LookupEnv("NR_LICENSE"); found {
		config.NrLicense = license
	}

	if passwd, found := os.LookupEnv("TUNNELBROKER_PASSWORD"); found {
		config.TunnelBroker.Password = passwd
	}

	// TODO: param validation

	return config
}
