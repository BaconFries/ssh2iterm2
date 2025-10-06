package main

import (
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/carlmjohnson/versioninfo"
	"github.com/mattn/go-isatty"
	"github.com/mitchellh/go-homedir"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"github.com/urfave/cli/altsrc"
	"github.com/youtube/vitess/go/ioutil2"
	"gopkg.in/yaml.v3"
)

var (
	// Version is the version string to be set at compile time via command line.
	version string
)

const (
	ColorBlack       = "#000000"
	ColorWhite       = "#FFFFFF"
	ColorRed         = "#FF0000"
	ColorGreen       = "#00FF00"
	ColorBlue        = "#0000FF"
	ColorSilver      = "#868686"
	ColorTransparent = "#00000000" // for alpha
)

func main() {

	configLogger()

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
	app.Version = getVersion()

	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		userHomeDir = "~/"
	}

	ssh, err := exec.LookPath("ssh")
	if err != nil {
		ssh = "ssh"
	}

	configPath := ""
	tierMapPath := ""
	userConfigDir, err := os.UserConfigDir()

	if err == nil {
		configPath = userConfigDir + "/ssh2iterm2.yaml"
		tierMapPath = userConfigDir + "/tier-map.yaml"
	}

	app.Flags = createAppFlags(ssh, userHomeDir, configPath, tierMapPath)

	app.Before = func(c *cli.Context) error {
		if _, err := os.Stat(configPath); !os.IsNotExist(err) {
			initConfig := altsrc.InitInputSourceWithContext(app.Flags, altsrc.NewYamlSourceFromFlagFunc("config"))
			_ = initConfig(c)
		}

		return nil
	}

	app.Commands = createAppCommands()

	err = app.Run(os.Args)

	if err != nil {
		logrus.Fatal(err)
	}
}

func configLogger() {
	logrus.SetFormatter(&logrus.TextFormatter{
		TimestampFormat: "2006-01-02 15:04:05",
		FullTimestamp:   true,
	})
	if isatty.IsTerminal(os.Stdout.Fd()) {
		logrus.SetOutput(os.Stdout)
		logrus.SetReportCaller(false)
	}
	logrus.SetLevel(logrus.DebugLevel)
}

func createAppFlags(ssh, _, configPath, tierMapPath string) []cli.Flag {
	return []cli.Flag{
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

		altsrc.NewStringFlag(cli.StringFlag{
			Name:   "prod_background",
			Usage:  "A file path to an image used for prodution background",
			EnvVar: "SSH2ITERM2_PROD_BACKGROUND",
		}),
		altsrc.NewStringFlag(cli.StringFlag{
			Name:   "lab_background",
			Usage:  "A file path to an image used for lab background",
			EnvVar: "SSH2ITERM2_LAB_BACKGROUND",
		}),
		altsrc.NewStringFlag(cli.StringFlag{
			Name:   "prod_badge_color",
			Usage:  "A hex color value for the prodution badge text",
			EnvVar: "SSH2ITERM2_PROD_BADGE_COLOR",
		}),
		altsrc.NewStringFlag(cli.StringFlag{
			Name:   "lab_badge_color",
			Usage:  "A hex color value for the lab badge text",
			EnvVar: "SSH2ITERM2_LAB_BADGE_COLOR",
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

		altsrc.NewStringFlag(cli.StringFlag{
			Name:      "tier-map",
			Value:     tierMapPath,
			Usage:     "A yaml file containing host prefix to tier mapping",
			EnvVar:    "SSH2ITERM2_TIER_MAP",
			TakesFile: true,
		}),
	}
}

func createAppCommands() []cli.Command {
	return []cli.Command{
		{
			Name:   "sync",
			Usage:  "Sync ssh config to iTerm2 dynamic profiles",
			Action: ssh2iterm2,
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
		{
			Name:   "edit-tier-map",
			Usage:  "Edit tier map file",
			Action: editConfig,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "editor",
					Value:  "vi",
					Usage:  "Use `EDITOR` to edit config file (create it of it doesn't exist)",
					EnvVar: "EDITOR",
				},
				cli.StringFlag{
					Name:  "type",
					Value: "tier-map",
				},
			},
		},
	}
}

func ssh2iterm2(c *cli.Context) error {
	r := regexp.MustCompile(`\*`)
	profiles := &profilelist{}
	automaticProfileSwitching := c.GlobalBool("automatic-profile-switching")
	suf := c.GlobalString("domain-suffix")
	ssh := c.GlobalString("ssh")
	logrus.Infof("SSH cli is %q", ssh)
	tiers, err := readTierConf(c.GlobalString("tier-map"))
	if err != nil {
		return err
	}

	awsSession := awsCreds(c.GlobalString("aws-profile"), c.GlobalString("aws-region"))
	awsmap, err := GetEC2InstanceTags(awsSession)
	if err != nil {
		return err
	}

	for _, am := range awsmap {
		if _, isEKS := am["eks:cluster-name"]; isEKS {
			logrus.Infof("Skipping EKS instance %s", am["Name"])
			continue
		}
		if _, isBuild := am["Ec2ImageBuilderArn"]; isBuild {
			logrus.Infof("Skipping Build instance %s", am["Name"])
			continue
		}
		if len(am["PrivateIpAddress"]) == 0 {
			logrus.Infof("Skipping No IP instance %s", am["Name"])
			continue
		}

		subsystem := strings.ToLower(am["Subsystem"])
		tier := getTier(tiers, am["Name"])
		hostname := am["Name"]
		domainname := hostname + suf
		name := hostname
		badge := hostname
		ip := am["PrivateIpAddress"]
		site := am["Site"]
		tag := subsystem
		backgroundImageLocation := ""

		logrus.WithFields(logrus.Fields{
			"site":      site,
			"hostname":  hostname,
			"subsystem": subsystem,
			"ip":        ip,
		}).Infof("Processing EC2 Instance")
		color := parseHexColor(ColorSilver)
		if len(site) > 0 {
			tag = fmt.Sprintf("%s/%s", site, subsystem)
			if tier != "" {
				tag = fmt.Sprintf("%s/%s/%s", site, subsystem, tier)
			}
			if site == "lab" {
				backgroundImageLocation = c.GlobalString("lab_background")
				color = parseHexColor(c.GlobalString("lab_badge_color"))
			} else if site == "use1" || site == "mgt1" {
				backgroundImageLocation = c.GlobalString("prod_background")
				color = parseHexColor(c.GlobalString("prod_badge_color"))
			}
		}

		match := r.MatchString(name)
		if !match {
			c := fmt.Sprintf("%q %q", ssh, domainname)
			if !strings.Contains(name, ".") {
				name = fmt.Sprintf("%s-%s", name, ip)
				badge = name
				c = fmt.Sprintf("%q -o %q %q", ssh, "StrictHostKeyChecking=no", "ec2-user@"+ip)
			}

			logrus.Infof("Identified %s", name)

			var boundHosts []string
			if automaticProfileSwitching {
				boundHosts = []string{hostname}
			}

			profiles.Profiles = append(profiles.Profiles, &profile{
				Badge:                   badge,
				GUID:                    generateUUIDFromString(name),
				Name:                    name,
				Command:                 c,
				CustomCommand:           "Yes",
				Tags:                    []string{tag},
				BoundHosts:              boundHosts,
				BackgroundImageLocation: backgroundImageLocation,
				BadgeColor:              color,
				BackgroundColor:         parseHexColor(ColorBlack),
			})
		}
	}

	sort.Slice(profiles.Profiles, func(i, j int) bool {
		// Compare by tags (assuming you want to sort by the first tag)
		if len(profiles.Profiles[i].Tags) > 0 && len(profiles.Profiles[j].Tags) > 0 {
			if profiles.Profiles[i].Tags[0] != profiles.Profiles[j].Tags[0] {
				return profiles.Profiles[i].Tags[0] < profiles.Profiles[j].Tags[0]
			}
		}

		// If the tags are identical, compare by name alphanumerically
		return alphanumericLess(profiles.Profiles[i].Name, profiles.Profiles[j].Name)
	})

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

	logrus.Infof("Writing %q", dynamicProfileFile)

	err = ioutil2.WriteFileAtomic(dynamicProfileFile, json, 0600)
	if err != nil {
		return err
	}

	return nil
}

func editConfig(ctx *cli.Context) error {
	configFile := ctx.GlobalString("config")
	configType := ctx.String("type")
	if configType == "tier-map" {
		configFile = ctx.GlobalString("tier-map")
	}

	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		conf := config{
			"ssh": ctx.GlobalString("ssh"),
		}
		if configType == "tier-map" {
			conf = config{
				"esfh":                      "hot",
				"esfw":                      "warm",
				"esfm":                      "master",
				"esfq":                      "query",
				"ui":                        "kibana",
				"!production":               "production",
				"!production-v2":            "production-v2",
				"!production-api-ingest":    "production-api-ingest",
				"!production-api-ingest-v2": "production-api-ingest-v2",
				"!production-api-beta":      "production-api-beta",
				"!production-api-beta-v2":   "production-api-beta-v2",
			}
		}
		err := createConfig(configFile, conf)
		if err != nil {
			return err
		}

	}

	editCmd := ctx.String("editor") + " '" + configFile + "'"
	cmd := exec.Command("sh", "-c", editCmd)

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run editor command: %w", err)
	}

	return nil
}

func createConfig(configFile string, config config) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config into YAML: %w", err)
	}

	err = ioutil2.WriteFileAtomic(configFile, data, 0o600)
	if err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

func awsCreds(profile, region string) *session.Session {
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: credentials.NewSharedCredentials("", profile),
	})
	if err != nil {
		logrus.Fatalf("AWS Session Error: %s", err.Error())
	}
	return sess
}

// GetEC2InstanceTags retrieves tags of EC2 instances and maps them by their IDs.
func GetEC2InstanceTags(s *session.Session) (map[string]map[string]string, error) {
	if s == nil {
		return nil, errors.New("session cannot be nil")
	}

	ec2IntMap := make(map[string]map[string]string)
	svc := ec2.New(s)
	input := &ec2.DescribeInstancesInput{}
	res, err := svc.DescribeInstances(input)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch Instance info from AWS: %w", err)
	}

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

	return ec2IntMap, nil
}

func getTier(tiers config, name string) string {
	for prefix, tier := range tiers {
		if strings.HasPrefix(prefix, "!") {
			if name == strings.TrimPrefix(prefix, "!") {
				return tier
			}
		}
		if strings.HasPrefix(name, prefix) {
			return tier
		}
	}
	return ""
}

func readTierConf(file string) (tiers config, err error) {
	configData, err := ioutil.ReadFile(file)
	if err != nil {
		logrus.Error("Error reading configuration file:", err)
		return
	}

	// Unmarshal the JSON data into the TiersConfig struct
	err = yaml.Unmarshal(configData, &tiers)
	if err != nil {
		logrus.Error("Error unmarshaling configuration data:", err)
		return
	}
	return
}

func generateUUIDFromString(input string) string {
	hasher := sha1.New()
	hasher.Write([]byte(input))
	hash := hasher.Sum(nil)
	uuidString := fmt.Sprintf("%x-%x-%x-%x-%x", hash[:4], hash[4:6], hash[6:8], hash[8:10], hash[10:])
	return uuidString
}

// parseHexColor converts a hex color string (e.g., "#FF5733" or "#F53") to a ColorComponent.
// Supports 3-digit (shorthand) and 6-digit hex colors. Alpha is optional (defaults to 1).
func parseHexColor(hexColor string) ColorComponent {
	// Default color (white)
	defaultColor := ColorComponent{
		RedComponent:   1,
		GreenComponent: 1,
		BlueComponent:  1,
		AlphaComponent: 1,
		ColorSpace:     "sRGB",
	}

	// Remove '#' prefix if present
	if len(hexColor) > 0 && hexColor[0] == '#' {
		hexColor = hexColor[1:]
	}

	// Validate length
	if len(hexColor) == 3 {
		// Convert 3-digit hex (e.g., "F53") to 6-digit (e.g., "FF5533")
		hexColor = fmt.Sprintf("%c%c%c%c%c%c", hexColor[0], hexColor[0], hexColor[1], hexColor[1], hexColor[2], hexColor[2])
	} else if len(hexColor) != 6 {
		// Invalid length
		return defaultColor
	}

	// Parse hex value
	var value uint32
	_, err := fmt.Sscanf(hexColor, "%x", &value)
	if err != nil {
		return defaultColor
	}

	// Extract components
	r := float64(uint8(value>>16)) / 255.0
	g := float64(uint8(value>>8)) / 255.0
	b := float64(uint8(value)) / 255.0

	return ColorComponent{
		RedComponent:   r,
		GreenComponent: g,
		BlueComponent:  b,
		AlphaComponent: 1,
		ColorSpace:     "sRGB",
	}
}

func getVersion() string {
	buildinfo, _ := debug.ReadBuildInfo()

	if version == "" {
		version = versioninfo.Revision

		if versioninfo.DirtyBuild {
			version += "-dirty"
		}
	}

	if buildinfo.Main.Version != "(devel)" {
		version = buildinfo.Main.Version
	}

	return version
}

// Helper function to split a string into its alphanumeric parts
func alphanumericLess(a, b string) bool {
	// Function to split a string into chunks of digits and non-digits
	split := func(r string) []string {
		re := regexp.MustCompile(`(\d+|\D+)`)
		return re.FindAllString(r, -1)
	}

	aParts := split(a)
	bParts := split(b)

	// Compare each part of the strings
	for i := 0; i < len(aParts) && i < len(bParts); i++ {
		aPart := aParts[i]
		bPart := bParts[i]

		// If both parts are numeric, compare them as numbers
		aNum, aErr := strconv.Atoi(aPart)
		bNum, bErr := strconv.Atoi(bPart)
		if aErr == nil && bErr == nil {
			if aNum != bNum {
				return aNum < bNum
			}
		} else {
			// Compare them as strings
			if aPart != bPart {
				return aPart < bPart
			}
		}
	}

	// If we compared all parts and they were the same, the shorter string is "less"
	return len(aParts) < len(bParts)
}
