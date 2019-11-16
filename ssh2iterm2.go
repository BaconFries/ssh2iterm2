package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kevinburke/ssh_config"
	"github.com/mattn/go-isatty"
	"github.com/mitchellh/go-homedir"
	"github.com/rjeczalik/notify"
	uuid "github.com/satori/go.uuid"
	"github.com/urfave/cli"
	"github.com/urfave/cli/altsrc"
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
	Profiles []*profile `json:",omitempty"`
}

// Version string to be set at compile time via command line (-ldflags "-X main.GitSummary=1.2.3")
var (
	GitSummary string
)

func main() {
	if isatty.IsTerminal(os.Stdout.Fd()) {
		log.SetFlags(0)
	}

	app := cli.NewApp()
	app.Name = "ssh2iterm2"
	app.Usage = "Create iTerm2 dynamic profile from SSH config"
	app.EnableBashCompletion = true
	app.Authors = []cli.Author{
		{
			Name:  "Arne Jørgensen",
			Email: "arne@arnested.dk",
		},
	}
	app.Version = GitSummary

	userHomeDir, err := os.UserHomeDir()

	if err != nil {
		userHomeDir = "~/"
	}

	ssh, err := exec.LookPath("ssh")

	if err != nil {
		ssh = "ssh"
	}

	configPath := ""
	userConfigDir, err := os.UserConfigDir()

	if err == nil {
		configPath = userConfigDir + "/ssh2iterm2.yaml"
	}

	app.Flags = []cli.Flag{
		altsrc.NewStringFlag(cli.StringFlag{
			Name:      "glob",
			Value:     userHomeDir + "/.ssh/config",
			Usage:     "A file `GLOB` matching ssh config file(s)",
			EnvVar:    "SSH2ITERM2_GLOB",
			TakesFile: true,
		}),
		altsrc.NewStringFlag(cli.StringFlag{
			Name:      "ssh",
			Value:     ssh,
			Usage:     "The ssh client `PATH`",
			EnvVar:    "SSH2ITERM2_SSH_PATH",
			TakesFile: true,
		}),
		cli.StringFlag{
			Name:      "config",
			Value:     configPath,
			Usage:     "Read config from `FILE`",
			EnvVar:    "SSH2ITERM2_CONFIG_FILE",
			TakesFile: true,
		},
	}

	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		app.Before = altsrc.InitInputSourceWithContext(app.Flags, altsrc.NewYamlSourceFromFlagFunc("config"))
	}

	app.Commands = []cli.Command{
		{
			Name:   "watch",
			Usage:  "Watch folder for changes",
			Action: watch,
		},
	}

	app.Action = ssh2iterm2

	err = app.Run(os.Args)

	if err != nil {
		log.Fatal(err)
	}
}

func ssh2iterm2(c *cli.Context) error {
	ns, err := uuid.FromString("CAAFD038-5E80-4266-B6CF-F4D036E092F4")

	if err != nil {
		return err
	}

	glob, err := homedir.Expand(c.GlobalString("glob"))

	if err != nil {
		return err
	}

	log.Printf("Glob is %q", glob)

	files, err := filepath.Glob(glob)
	if err != nil {
		return err
	}

	r := regexp.MustCompile(`\*`)

	profiles := &profilelist{}

	ssh := c.GlobalString("ssh")
	log.Printf("SSH cli is %q", ssh)

	for _, file := range files {
		processFile(file, r, ssh, ns, profiles)
	}

	json, err := json.MarshalIndent(profiles, "", "    ")

	if err != nil {
		return err
	}

	userConfigDir, err := os.UserConfigDir()

	if err != nil {
		return err
	}

	dynamicProfileFile, err := homedir.Expand(userConfigDir + "/iTerm2/DynamicProfiles/ssh2iterm2.json")

	if err != nil {
		return err
	}

	log.Printf("Writing %q", dynamicProfileFile)
	err = ioutil2.WriteFileAtomic(dynamicProfileFile, json, 0644)
	if err != nil {
		return err
	}

	return nil
}

func processFile(file string, r *regexp.Regexp, ssh string, ns uuid.UUID, profiles *profilelist) {
	log.Printf("Parsing %q", file)
	fileContent, err := os.Open(file)

	if err != nil {
		log.Print(err)
		return
	}

	cfg, err := ssh_config.Decode(fileContent)

	if err != nil {
		log.Print(err)
	}

	tag := tag(file)

	for _, host := range cfg.Hosts {
		for _, pattern := range host.Patterns {
			hostname := pattern.String()
			name := hostname
			badge := hostname
			comment := strings.TrimSpace(host.EOLComment)
			if comment != "" {
				badge = comment
				name = fmt.Sprintf("%s (%s)", hostname, comment)
			}
			match := r.MatchString(name)
			if !match {
				uuid := uuid.NewV5(ns, name).String()
				log.Printf("Identified %s", name)
				profiles.Profiles = append(profiles.Profiles, &profile{
					Badge:         badge,
					GUID:          uuid,
					Name:          name,
					Command:       fmt.Sprintf("%q %q", ssh, hostname),
					CustomCommand: "Yes",
					Triggers: &triggerlist{&trigger{
						Partial:   true,
						Parameter: hostname,
						Regex:     "\\[sudo\\] password for",
						Action:    "PasswordTrigger",
					}},
					Tags: []string{tag},
				})
			}
		}
	}
}

func tag(filename string) string {
	base := path.Base(strings.TrimSuffix(filename, path.Ext(filename)))
	re := regexp.MustCompile(`^[0-9]+_`)
	return re.ReplaceAllString(base, `$1`)
}

func watch(c *cli.Context) error {
	glob, err := homedir.Expand(c.GlobalString("glob"))

	if err != nil {
		return err
	}

	dir := filepath.Dir(strings.SplitAfterN(glob, "*", 2)[0])
	log.Printf("Watching is %q", dir)

	eventChan := make(chan notify.EventInfo, 10)

	if err := notify.Watch(dir+"/...", eventChan, notify.All); err != nil {
		log.Fatal(err)
	}

	defer notify.Stop(eventChan)

	for {
		eventInfo := <-eventChan
		if match, err := filepath.Match(glob, eventInfo.Path()); err == nil && match {
			_ = ssh2iterm2(c)
		}
	}
}
