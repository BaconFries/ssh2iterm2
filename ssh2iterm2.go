package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/carlmjohnson/versioninfo"
	"github.com/mattn/go-isatty"
	"github.com/mitchellh/go-homedir"
	"github.com/natefinch/atomic"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"
)

var version string

// Config types
type AppConfig struct {
	SSH                       string                `yaml:"ssh,omitempty"`
	AutomaticProfileSwitching bool                  `yaml:"automatic-profile-switching,omitempty"`
	DomainSuffix              string                `yaml:"domain-suffix,omitempty"`
	ExcludeHostsMatching      []string              `yaml:"exclude_hosts_matching,omitempty"`
	DynamicProfileParentName  string                `yaml:"dynamic-profile-parent-name"`
	AWSProfiles               map[string]AWSProfile `yaml:"aws_profiles,omitempty"`
}

type AWSProfile struct {
	AWSRegion string          `yaml:"aws_region,omitempty"`
	Sites     map[string]Site `yaml:"sites,omitempty"`
}
type Site struct {
	Background string `yaml:"background,omitempty"`
	BadgeColor string `yaml:"badge_color,omitempty"`
}

// iTerm2 profile types
type profile struct {
	Badge                   string         `json:"Badge Text"`
	GUID                    string         `json:"Guid"`
	Name                    string         `json:"Name"`
	Command                 string         `json:"Command"`
	CustomCommand           string         `json:"Custom Command"`
	Tags                    []string       `json:"Tags,omitempty"`
	BoundHosts              []string       `json:"Bound Hosts,omitempty"`
	BackgroundImageLocation string         `json:"Background Image Location,omitempty"`
	BadgeColor              ColorComponent `json:"Badge Color"`
	BackgroundColor         ColorComponent `json:"Background Color"`
	ForegroundColor         ColorComponent `json:"Foreground Color"`
}

type ColorComponent struct {
	RedComponent   float64 `json:"Red Component"`
	GreenComponent float64 `json:"Green Component"`
	BlueComponent  float64 `json:"Blue Component"`
	AlphaComponent float64 `json:"Alpha Component"`
	ColorSpace     string  `json:"Color Space"`
}

type profilelist struct {
	Profiles []*profile `json:"Profiles"`
}

const (
	ColorBlack       = "#000000"
	ColorWhite       = "#FFFFFF"
	ColorRed         = "#FF0000"
	ColorGreen       = "#00FF00"
	ColorBlue        = "#0000FF"
	ColorSilver      = "#868686"
	ColorViolet      = "#B200ED"
	ColorTransparent = "#00000000" // for alpha
)

func main() {
	configLogger()

	configPath := ""
	tierMapPath := ""
	userConfigDir, err := os.UserConfigDir()

	if err == nil {
		configPath = userConfigDir + "/ssh2iterm2.yaml"
		tierMapPath = userConfigDir + "/tier-map.yaml"
	}

	app := &cli.App{
		Name:                 "ssh2iterm2",
		Usage:                "Generate iTerm2 dynamic profiles from AWS EC2 instances",
		Version:              getVersion(),
		EnableBashCompletion: true,
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "config", Value: configPath, Usage: "Config file"},
			&cli.StringFlag{Name: "tier-map", Value: tierMapPath, Usage: "Tier mapping file"},
			&cli.StringFlag{Name: "ssh", Value: "ssh", Usage: "SSH binary", EnvVars: []string{"SSH2ITERM2_SSH"}},
			&cli.StringFlag{Name: "domain-suffix", Value: ".internal", Usage: "Domain suffix", EnvVars: []string{"SSH2ITERM2_DOMAIN_SUFFIX"}},
			&cli.BoolFlag{Name: "automatic-profile-switching", Usage: "Enable auto profile switching", EnvVars: []string{"SSH2ITERM2_AUTO_SWITCH"}},
		},
		Commands: []*cli.Command{
			{Name: "sync", Usage: "Generate iTerm2 profiles from EC2", Action: ssh2iterm2},
			{Name: "edit-config", Usage: "Edit main config (creates if missing)", Action: editConfigCmd},
			{Name: "edit-tier-map", Usage: "Edit tier map (creates if missing)", Action: editTierMapCmd},
		},
	}

	if err := app.Run(os.Args); err != nil {
		logrus.Fatal(err)
	}
}

func configLogger() {
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})
	if isatty.IsTerminal(os.Stdout.Fd()) {
		logrus.SetOutput(os.Stdout)
	}
	logrus.SetLevel(logrus.InfoLevel)
	if os.Getenv("DEBUG") != "" {
		logrus.SetLevel(logrus.DebugLevel)
	}
}

func ssh2iterm2(c *cli.Context) error {
	cfg := loadConfig(c)
	tiers, _ := readTierMap(c.String("tier-map"))
	profiles := &profilelist{}

	instances := []map[string]string{}

	// Gather instances from configured sites
	fmt.Printf("cfg: %+v\n", cfg)
	if len(cfg.AWSProfiles) > 0 {
		for awsProfileName, awsProfile := range cfg.AWSProfiles {
			fmt.Printf("awsProfileName: %v\n", awsProfileName)
			fmt.Printf("awsProfile.AWSRegion: %v\n", awsProfile.AWSRegion)
			awsCfg, err := createAWSSession(awsProfileName, awsProfile.AWSRegion)
			if err != nil {
				logrus.Warnf("awsProfileName %s: failed to load AWS config: %v", awsProfileName, err)
				continue
			}
			insts, err := describeEC2Instances(awsCfg)
			if err != nil {
				logrus.Errorf("awsProfileName %s: failed to describe instances: %v", awsProfileName, err)
				continue
			}

			for i := range insts {
				site, ok := insts[i]["Site"]
				if !ok {
					continue
				}
				_, exists := awsProfile.Sites[site]
				if !exists {
					continue
				}
				insts[i]["_Site"] = site
				if awsProfile.Sites[site].Background != "" {
					insts[i]["_Background"] = awsProfile.Sites[site].Background
				}
				if awsProfile.Sites[site].BadgeColor != "" {
					insts[i]["_BadgeColor"] = awsProfile.Sites[site].BadgeColor
				}
			}
			instances = append(instances, insts...)
			logrus.Infof("Loaded %d instances from awsProfileName: %s", len(insts), awsProfileName)
		}
	} else {
		logrus.Info("No sites in config — done")
		os.Exit(1)
	}

	// Default exclude patterns
	exclude := cfg.ExcludeHostsMatching
	if len(exclude) == 0 {
		exclude = []string{"*bastion*", "*jump*", "*proxy*", "*-vpn-*", "monitoring-*"}
	}

	for _, tags := range instances {
		hostname := coalesce(tags["Name"], tags["InstanceId"], "")
		if hostname == "" {
			continue
		}

		// Exclude unwanted hosts
		skip := false
		for _, pat := range exclude {
			if ok, _ := filepath.Match(strings.ToLower(pat), strings.ToLower(hostname)); ok {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		ip := tags["PrivateIpAddress"]
		if ip == "" {
			continue
		}

		site := coalesce(tags["_Site"], "default")
		subsystem := strings.ToLower(coalesce(tags["Subsystem"], "app"))
		tier := getTier(tiers, hostname)

		tag := site + "/" + subsystem
		if tier != "" {
			tag += "/" + tier
		}

		background := tags["_Background"]
		badgeColor := parseHexColor(coalesce(tags["_BadgeColor"], ColorSilver))

		name := hostname
		badge := hostname
		command := fmt.Sprintf("%q %s%s", cfg.SSH, hostname, cfg.DomainSuffix)

		if !strings.Contains(hostname, ".") {
			cleanIP := strings.ReplaceAll(ip, ".", "-")
			name = fmt.Sprintf("%s-%s", hostname, cleanIP)
			badge = name
			command = fmt.Sprintf("%q -o StrictHostKeyChecking=no ec2-user@%s", cfg.SSH, ip)
		}

		var boundHosts []string
		if cfg.AutomaticProfileSwitching {
			boundHosts = []string{hostname, hostname + cfg.DomainSuffix}
		}

		profiles.Profiles = append(profiles.Profiles, &profile{
			Badge:                   badge,
			GUID:                    generateUUIDFromString(name + site),
			Name:                    name,
			Command:                 command,
			CustomCommand:           "Yes",
			Tags:                    []string{tag},
			BoundHosts:              boundHosts,
			BackgroundImageLocation: background,
			BadgeColor:              badgeColor,
			BackgroundColor:         parseHexColor(ColorBlack),
			ForegroundColor:         parseHexColor(ColorWhite),
		})
	}

	// Sort profiles
	sort.Slice(profiles.Profiles, func(i, j int) bool {
		if len(profiles.Profiles[i].Tags) == 0 || len(profiles.Profiles[j].Tags) == 0 {
			return profiles.Profiles[i].Name < profiles.Profiles[j].Name
		}
		if profiles.Profiles[i].Tags[0] != profiles.Profiles[j].Tags[0] {
			return profiles.Profiles[i].Tags[0] < profiles.Profiles[j].Tags[0]
		}
		return alphanumericLess(profiles.Profiles[i].Name, profiles.Profiles[j].Name)
	})

	// Write output
	userConfigDir, _ := os.UserConfigDir()
	jsonData, _ := json.MarshalIndent(profiles, "", "    ")
	outPath, _ := homedir.Expand(userConfigDir + "/iTerm2/DynamicProfiles/ssh2iterm2.json")
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return err
	}
	if err := atomic.WriteFile(outPath, bytes.NewReader(jsonData)); err != nil {
		return err
	}

	logrus.Infof("Success: Wrote %d profiles → %s", len(profiles.Profiles), outPath)
	return nil
}

func loadConfig(c *cli.Context) AppConfig {
	var fileCfg AppConfig

	path, _ := homedir.Expand(c.String("config"))
	fmt.Printf("path: %v\n", path)

	if data, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(data, &fileCfg); err != nil {
			logrus.Warnf("Failed to unmarshal config: %v", err)
		}
	} else if !os.IsNotExist(err) {
		logrus.Warnf("Failed to read config file: %v", err)
	}
	cfg := fileCfg
	if c.IsSet("ssh") {
		cfg.SSH = c.String("ssh")
	}
	if c.IsSet("domain-suffix") {
		cfg.DomainSuffix = c.String("domain-suffix")
	}
	if c.IsSet("automatic-profile-switching") {
		cfg.AutomaticProfileSwitching = c.Bool("automatic-profile-switching")
	}
	if c.IsSet("dynamic-profile-parent-name") {
		cfg.DynamicProfileParentName = c.String("dynamic-profile-parent-name")
	}

	// Apply Hardcoded Defaults if the value is still empty
	if cfg.DynamicProfileParentName == "" {
		cfg.DynamicProfileParentName = "Default" // Your previous hardcoded default
	}
	if cfg.DomainSuffix == "" {
		cfg.DomainSuffix = ".internal"
	}

	fmt.Printf("cfg: %v\n", cfg)
	return cfg
}

func createAWSSession(profile, region string) (aws.Config, error) {
	opts := []func(*config.LoadOptions) error{}
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	return config.LoadDefaultConfig(context.TODO(), opts...)
}

func describeEC2Instances(cfg aws.Config) ([]map[string]string, error) {
	client := ec2.NewFromConfig(cfg)
	var instances []map[string]string

	paginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			return nil, err
		}
		for _, r := range page.Reservations {
			for _, i := range r.Instances {
				tags := map[string]string{}
				for _, t := range i.Tags {
					if strings.HasPrefix(aws.ToString(t.Key), "aws:") {
						continue
					}
					tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
				}
				if i.PrivateIpAddress != nil {
					tags["PrivateIpAddress"] = aws.ToString(i.PrivateIpAddress)
				}
				if i.InstanceId != nil {
					tags["InstanceId"] = aws.ToString(i.InstanceId)
				}
				if name := tags["Name"]; name == "" {
					tags["Name"] = tags["InstanceId"]
				}
				instances = append(instances, tags)
			}
		}
	}
	return instances, nil
}

func readTierMap(path string) (map[string]string, error) {
	path, _ = homedir.Expand(path)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return map[string]string{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	return m, yaml.Unmarshal(data, &m)
}

func getTier(tiers map[string]string, name string) string {
	for prefix, tier := range tiers {
		if strings.HasPrefix(prefix, "!") && name == strings.TrimPrefix(prefix, "!") {
			return tier
		}
	}
	for prefix, tier := range tiers {
		if !strings.HasPrefix(prefix, "!") && strings.HasPrefix(name, prefix) {
			return tier
		}
	}
	return ""
}

func generateUUIDFromString(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%12x", bs[0:4], bs[4:6], bs[6:8], bs[8:10], bs[10:])
}

func parseHexColor(hex string) ColorComponent {
	if hex == "" {
		hex = "#FFFFFF"
	}
	if hex[0] == '#' {
		hex = hex[1:]
	}
	if len(hex) == 3 {
		hex = hex[0:1] + hex[0:1] + hex[1:2] + hex[1:2] + hex[2:3] + hex[2:3]
	}
	var r, g, b uint8
	fmt.Sscanf(hex, "%02x%02x%02x", &r, &g, &b)
	f := 255.0
	return ColorComponent{
		RedComponent:   float64(r) / f,
		GreenComponent: float64(g) / f,
		BlueComponent:  float64(b) / f,
		AlphaComponent: 1.0,
		ColorSpace:     "sRGB",
	}
}

func coalesce(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func alphanumericLess(a, b string) bool {
	re := regexp.MustCompile(`(\d+|\D+)`)
	pa := re.FindAllString(a, -1)
	pb := re.FindAllString(b, -1)
	for i := 0; i < len(pa) && i < len(pb); i++ {
		if pa[i] != pb[i] {
			if na, erra := strconv.Atoi(pa[i]); erra == nil {
				if nb, errb := strconv.Atoi(pb[i]); errb == nil {
					return na < nb
				}
			}
			return pa[i] < pb[i]
		}
	}
	return len(pa) < len(pb)
}

func editConfigCmd(c *cli.Context) error {
	return editFile(c.String("config"), defaultConfig())
}

func editTierMapCmd(c *cli.Context) error {
	return editFile(c.String("tier-map"), defaultTierMap())
}

func editFile(pathStr, defaultContent string) error {
	path, err := homedir.Expand(pathStr)
	if err != nil {
		return fmt.Errorf("failed to expand path %q: %w", pathStr, err)
	}

	// Create config with default content if missing
	if _, err := os.Stat(path); os.IsNotExist(err) {
		logrus.Infof("Creating default config: %s", path)
		if err := atomic.WriteFile(path, bytes.NewReader([]byte(defaultContent))); err != nil {
			return fmt.Errorf("failed to create config file: %w", err)
		}
	}

	// Use $EDITOR or fallback to vi
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}

	cmd := exec.Command("sh", "-c", fmt.Sprintf("%s %q", editor, path))
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

func defaultConfig() string {
	return `# ~/.config/ssh2iterm2.yaml
ssh: /opt/homebrew/bin/ssh
automatic-profile-switching: true
domain-suffix: .netog.io

exclude_hosts_matching:
  - "*bastion*"
  - "*jump*"
  - "*-vpn-*"

aws_profiles:
  default:
    aws_region: us-east-1
    sites:
      use1:
        background:  ~/Pictures/red-bg.png
        badge_color: "#FF240
`
}

func defaultTierMap() string {
	return `# ~/.config/tier-map.yaml
"!production": production
"!production-v2": production-v2
esfh: hot
esfw: warm
esfm: master
esfq: query
ui: kibana
alert-f: filter
alert-t: trigger
`
}

func getVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return versioninfo.Revision
}
