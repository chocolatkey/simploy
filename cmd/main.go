package main

import (
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/chocolatkey/simploy"
	"github.com/sirupsen/logrus"
)

func main() {
	logrus.SetReportCaller(true)
	logrus.SetOutput(os.Stdout)
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	logrus.SetLevel(logrus.DebugLevel)

	// Parse config
	bin, err := ioutil.ReadFile("./config.json")
	if err != nil {
		logrus.Fatal(err)
	}
	var rawConfig simploy.RawConfig
	err = json.Unmarshal(bin, &rawConfig)
	if err != nil {
		logrus.Fatal(err)
	}

	// Parse repos
	bin, err = ioutil.ReadFile("./repos.json")
	if err != nil {
		logrus.Fatal(err)
	}
	var repos []simploy.RepoConfig
	err = json.Unmarshal(bin, &repos)
	if err != nil {
		logrus.Fatal(err)
	}

	simploy.Run(rawConfig, repos)
}
