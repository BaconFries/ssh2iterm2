package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/google/gops/agent"
	"github.com/google/uuid"
	"github.com/kevinburke/ssh_config"
	"github.com/mattn/go-isatty"
	"github.com/mitchellh/go-homedir"
	"github.com/rjeczalik/notify"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"github.com/urfave/cli/altsrc"
	"github.com/youtube/vitess/go/ioutil2"
	"gopkg.in/yaml.v3"
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
	BoundHosts    []string     `json:"Bound Hosts,omitempty"`
}

type hostjson struct {
	Name             string `json:"name"`
	PrivateIpAddress string `json:"privateip"`
	Subsystem        string `json:"subsystem"`
	Site             string `json:"site"`
	Comment          string `json:"comment"`
}

type triggerlist []*trigger

type profilelist struct {
	Profiles []*profile `json:",omitempty"`
}

// GitSummary is the version string to be set at compile time via command line.
var GitSummary string //nolint:gochecknoglobals

//nolint:funlen // needs refactoring.
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
			Name:   "domain-suffix",
			Usage:  "Domain name suffix",
			EnvVar: "SSH2ITERM2_DN_SUFFIX",
		}),
		altsrc.NewStringFlag(cli.StringFlag{
			Name:   "aws-profile",
			Usage:  "aws profile name",
			EnvVar: "SSH2ITERM2_AWS_PROFILE",
		}),
		altsrc.NewStringFlag(cli.StringFlag{
			Name:   "aws-region",
			Usage:  "aws region",
			EnvVar: "SSH2ITERM2_AWS_REGION",
		}),
		altsrc.NewBoolFlag(cli.BoolFlag{
			Name:   "aws",
			Usage:  "search aws for hosts",
			EnvVar: "SSH2ITERM2_AWS",
		}),
		altsrc.NewBoolFlag(cli.BoolFlag{
			Name:   "json",
			Usage:  "A json host file use bool",
			EnvVar: "SSH2ITERM2_JSON",
		}),
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
		altsrc.NewBoolFlag(cli.BoolFlag{
			Name:   "automatic-profile-switching",
			Usage:  "Add hostname for automatic profile switching`",
			EnvVar: "SSH2ITERM2_AUTOMATIC_PROFILE_SWITCHING",
		}),
		cli.StringFlag{
			Name:      "config",
			Value:     configPath,
			Usage:     "Read config from `FILE`",
			EnvVar:    "SSH2ITERM2_CONFIG_FILE",
			TakesFile: true,
		},
		altsrc.NewBoolFlag(cli.BoolFlag{
			Name:   "enable-gops-agent",
			Usage:  "Run with a gops agent (see https://pkg.go.dev/github.com/google/gops?tab=overview)",
			EnvVar: "SSH2ITERM2_WITH_GOPS_AGENT",
		}),
	}

	app.Before = func(c *cli.Context) error {
		if _, err := os.Stat(configPath); !os.IsNotExist(err) {
			initConfig := altsrc.InitInputSourceWithContext(app.Flags, altsrc.NewYamlSourceFromFlagFunc("config"))
			_ = initConfig(c)
		}

		if c.GlobalBool("enable-gops-agent") {
			if err := agent.Listen(agent.Options{ShutdownCleanup: true}); err != nil {
				log.Fatal(err)
			}
		}

		return nil
	}

	app.Commands = []cli.Command{
		{
			Name:   "sync",
			Usage:  "Sync ssh config to iTerm2 dynamic profiles",
			Action: ssh2iterm2,
		},
		{
			Name:   "watch",
			Usage:  "Continuously watch and sync folder for changes",
			Action: watch,
		},
		{
			Name:   "edit-config",
			Usage:  "Edit config file",
			Action: editConfig,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "editor",
					Value:  "vi",
					Usage:  "Use `EDITOR` to edit config file (create it of it doesn't exist)",
					EnvVar: "EDITOR",
				},
			},
		},
	}

	err = app.Run(os.Args)

	if err != nil {
		log.Fatal(err)
	}
}

func ssh2iterm2(c *cli.Context) error {
	ns, err := uuid.Parse("CAAFD038-5E80-4266-B6CF-F4D036E092F4")
	if err != nil {
		return err
	}
	r := regexp.MustCompile(`\*`)
	profiles := &profilelist{}
	automaticProfileSwitching := c.GlobalBool("automatic-profile-switching")
	found := c.GlobalBool("json")
	suf := c.GlobalString("domain-suffix")
	ssh := c.GlobalString("ssh")
	log.Printf("SSH cli is %q", ssh)

	if c.GlobalBool("aws") {
		awsSession := awsCreds(c.GlobalString("aws-profile"), c.GlobalString("aws-region"))
		awsmap, err := Ec2IntMapper(awsSession)
		if err != nil {
			return err
		}
		var hj []hostjson
		for _, am := range awsmap {
			if am["Subsystem"] == "portal" {
				fmt.Printf("%+v\n", am["Name"])
				fmt.Printf("%+v\n", am["PrivateIP"])
			}
			hj = append(hj, hostjson{
				Name:             am["Name"],
				PrivateIpAddress: am["PrivateIpAddress"],
				Subsystem:        strings.ToLower(am["Subsystem"]),
				Site:             am["Site"],
				Comment:          "",
			})
		}
		processJson(hj, r, ssh, ns, profiles, automaticProfileSwitching, suf)
	} else {
		glob, err := homedir.Expand(c.GlobalString("glob"))
		if err != nil {
			return err
		}

		log.Printf("Glob is %q", glob)

		files, err := filepath.Glob(glob)
		if err != nil {
			return err
		}

		for _, file := range files {
			if found {
				var hj []hostjson
				var fileContent *os.File
				byteValue, _ := ioutil.ReadAll(fileContent)
				if err := json.Unmarshal(byteValue, &hj); err != nil {
					panic(err)
				}
				processJson(hj, r, ssh, ns, profiles, automaticProfileSwitching, suf)
			} else {
				processFile(file, r, ssh, ns, profiles, automaticProfileSwitching)
			}
		}
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
	//fmt.Printf("%+v\n", string(json))

	err = ioutil2.WriteFileAtomic(dynamicProfileFile, json, 0600)
	if err != nil {
		return err
	}

	return nil
}

//nolint:funlen // needs refactoring.
func processFile(file string,
	r *regexp.Regexp,
	ssh string,
	ns uuid.UUID,
	profiles *profilelist,
	automaticProfileSwitching bool,
) {
	log.Printf("Parsing %q", file)

	fileContent, err := os.Open(file)
	if err != nil {
		log.Print(err)
		return
	}
	cfg, err := ssh_config.Decode(fileContent)
	if err != nil {
		log.Print(err)
		return
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
				uuid := uuid.NewSHA1(ns, []byte(name)).String()
				log.Printf("Identified %s", name)

				var boundHosts []string
				if automaticProfileSwitching {
					boundHosts = []string{hostname}
				}

				profiles.Profiles = append(profiles.Profiles, &profile{
					Badge:         badge,
					GUID:          uuid,
					Name:          name,
					Command:       fmt.Sprintf("%q %q", ssh, hostname),
					CustomCommand: "Yes",
					Triggers: &triggerlist{&trigger{
						Partial:   true,
						Parameter: "\\1@\\2\n\\1@\\2",
						Regex:     "^\\[?([\\w-.]+)@([\\w-.]+)",
						Action:    "SetHostnameTrigger",
					}},
					Tags:       []string{tag},
					BoundHosts: boundHosts,
				})
			}
		}
	}

}

//nolint:funlen // needs refactoring.
func processJson(hj []hostjson,
	r *regexp.Regexp,
	ssh string,
	ns uuid.UUID,
	profiles *profilelist,
	automaticProfileSwitching bool,
	domain_suffix string,
) {

	for _, host := range hj {

		hostname := host.Name
		name := hostname
		badge := hostname
		ip := host.PrivateIpAddress
		comment := host.Comment
		tag := host.Subsystem
		if len(host.Site) > 0 {
			tag = fmt.Sprintf("%s/%s", host.Site, host.Subsystem)
		}
		if comment != "" {
			badge = comment
			name = fmt.Sprintf("%s (%s)", hostname, comment)
		}

		match := r.MatchString(name)
		if !match {
			c := fmt.Sprintf("%q %q", ssh, hostname+domain_suffix)
			if !strings.Contains(name, ".") {
				name = fmt.Sprintf("%s-%s", name, ip)
				badge = name
				c = fmt.Sprintf("%q -o %q %q", ssh, "StrictHostKeyChecking=no", "ec2-user@"+ip)
			}

			uuid := uuid.NewSHA1(ns, []byte(name)).String()
			log.Printf("Identified %s", name)

			var boundHosts []string
			if automaticProfileSwitching {
				boundHosts = []string{hostname}
			}

			profiles.Profiles = append(profiles.Profiles, &profile{
				Badge:         badge,
				GUID:          uuid,
				Name:          name,
				Command:       c,
				CustomCommand: "Yes",
				Triggers: &triggerlist{&trigger{
					Partial:   true,
					Parameter: "\\1@\\2\n\\1@\\2",
					Regex:     "^\\[?([\\w-.]+)@([\\w-.]+)",
					Action:    "SetHostnameTrigger",
				}},
				Tags:       []string{tag},
				BoundHosts: boundHosts,
			})
		}

	}

}

func tag(filename string) string {
	base := path.Base(strings.TrimSuffix(filename, path.Ext(filename)))
	re := regexp.MustCompile(`^[0-9]+_`)

	return re.ReplaceAllString(base, `$1`)
}

const channelBufferSize = 10

func watch(c *cli.Context) error {
	glob, err := homedir.Expand(c.GlobalString("glob"))
	if err != nil {
		return err
	}

	dir := filepath.Dir(strings.SplitAfterN(glob, "*", 2)[0])
	log.Printf("Watching is %q", dir)

	eventChan := make(chan notify.EventInfo, channelBufferSize)

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

type config struct {
	Json string `yaml:"json"`
	Glob string `yaml:"glob"`
	SSH  string `yaml:"ssh"`
}

func editConfig(c *cli.Context) error {
	configFile := c.GlobalString("config")

	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		err := createConfig(configFile, config{
			Json: c.GlobalString("json"),
			Glob: c.GlobalString("glob"),
			SSH:  c.GlobalString("ssh"),
		})
		if err != nil {
			return err
		}
	}

	editCmd := c.String("editor") + " '" + configFile + "'"
	cmd := exec.Command("sh", "-c", editCmd)

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

func createConfig(configFile string, config config) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(configFile, data, 0600)
	if err != nil {
		return err
	}

	return nil
} //nolint:gofumpt // false lint error with golangci-lint.

func awsCreds(profile, region string) *session.Session {
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: credentials.NewSharedCredentials("", profile),
	})
	if err != nil {
		fmt.Printf("AWS Session Error: %+v\n", err)
		os.Exit(1)
	}
	return sess
}

// Ec2IntMapper creates map of ec2 instances IDs and their tags
func Ec2IntMapper(s *session.Session) (map[string]map[string]string, error) {

	ec2IntMap := make(map[string]map[string]string)
	if s != nil {
		svc := ec2.New(s)
		input := &ec2.DescribeInstancesInput{}
		res, err := svc.DescribeInstances(input)
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				default:
					logrus.WithFields(logrus.Fields{
						"error": aerr,
					}).Error("Unable to fetch Instance info from AWS")
				}
			} else {
				logrus.WithFields(logrus.Fields{
					"error": err,
				}).Error("Unable to fetch Instance info from AWS")
			}
			return ec2IntMap, err
		}
		//fmt.Printf("res: %+v\n", res)
		for _, a := range res.Reservations {
			for _, b := range a.Instances {
				tags := make(map[string]string)
				for _, t := range b.Tags {
					if strings.HasPrefix(*t.Key, "aws:") {
						continue
					}
					tags[*t.Key] = *t.Value
				}
				if b.PrivateIpAddress != nil {
					tags["PrivateIpAddress"] = *b.PrivateIpAddress
				}

				ec2IntMap[*b.InstanceId] = tags
			}
		}
	}
	return ec2IntMap, nil
}
