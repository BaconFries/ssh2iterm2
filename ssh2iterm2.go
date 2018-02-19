package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/mikkeloscar/sshconfig"
	homedir "github.com/mitchellh/go-homedir"
	uuid "github.com/satori/go.uuid"
	"github.com/youtube/vitess/go/ioutil2"
)

type trigger struct {
	Partial   bool   `json:"partial"`
	Parameter string `json:"parameter"`
	Regex     string `json:"regex"`
	Action    string `json:"action"`
}

type profile struct {
	Badge         string `json:"Badge Text"`
	GUID          string `json:"Guid"`
	Name          string
	Command       string
	CustomCommand string       `json:"Custom Command"`
	Triggers      *triggerlist `json:",omitempty"`
	Tags          []string     `json:",omitempty"`
}

type triggerlist []*trigger

type profilelist struct {
	Profiles []*profile
}

func main() {
	ns, _ := uuid.FromString("CAAFD038-5E80-4266-B6CF-F4D036E092F4")

	glob, present := os.LookupEnv("SSH2ITERM2_GLOB")

	if !present {
		glob = "~/.ssh/config"
	}

	sshconfGlob, _ := homedir.Expand(glob)
	files, _ := filepath.Glob(sshconfGlob)

	profiles := &profilelist{}

	for _, file := range files {
		hosts, _ := sshconfig.ParseSSHConfig(file)
		tag := tag(file)

		for _, host := range hosts {
			for _, name := range host.Host {
				match, _ := regexp.MatchString("\\*", name)
				if !match {
					uuid := uuid.NewV5(ns, name).String()
					profiles.Profiles = append(profiles.Profiles, &profile{
						Badge:         name,
						GUID:          uuid,
						Name:          name,
						Command:       fmt.Sprintf("sh -c 'PATH=/usr/local/bin:$PATH ssh %s'", name),
						CustomCommand: "Yes",
						Triggers: &triggerlist{&trigger{
							Partial:   true,
							Parameter: name,
							Regex:     "\\[sudo\\] password for",
							Action:    "PasswordTrigger",
						}},
						Tags: []string{tag},
					})
				}
			}
		}
	}

	json, err := json.MarshalIndent(profiles, "", "    ")

	if err != nil {
		panic(err)
	}

	if 0 == len(profiles.Profiles) {
		panic(errors.New("No profiles."))
	}

	dynamicProfileFile, _ := homedir.Expand("~/Library/Application Support/iTerm2/DynamicProfiles/ssh.json")
	ioutil2.WriteFileAtomic(dynamicProfileFile, json, 0644)
}

func tag(filename string) string {
	base := path.Base(strings.TrimSuffix(filename, path.Ext(filename)))
	var re = regexp.MustCompile(`^[0-9]+_`)
	return re.ReplaceAllString(base, `$1`)
}
