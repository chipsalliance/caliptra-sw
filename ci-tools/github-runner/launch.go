// Licensed under the Apache-2.0 license

package runner

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"github.com/google/go-github/v53/github"
	"google.golang.org/protobuf/proto"

	ghinstallation "github.com/bradleyfalzon/ghinstallation/v2"
)

//go:embed scripts/launch_runner.sh
var launchStartupScript string

func randId() string {
	result := make([]byte, 16)
	_, err := rand.Read(result)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(result)
}

func GithubClient(appID int64, installationID int64) (*github.Client, error) {
	transport, err := ghinstallation.NewKeyFromFile(http.DefaultTransport, appID, installationID, "/etc/secrets/caliptra-gce-ci-github-private-key-pem/latest")
	if err != nil {
		return nil, err
	}
	return github.NewClient(&http.Client{Transport: transport}), nil
}

type RunnerInfo struct {
	Name      string
	JitConfig string
}

type MachineConfig struct {
	MachineTypeLabel string
}

func GitHubRegisterRunner(ctx context.Context, client *github.Client, labels []string, name string) (RunnerInfo, error) {
	if name == "" {
		name = fmt.Sprintf("gce-github-runner-%v", randId())
	}
	jitConfig, response, err := client.Actions.GenerateOrgJITConfig(ctx, githubOrg, &github.GenerateJITConfigRequest{
		Name:          name,
		RunnerGroupID: 1,
		Labels:        labels,
	})
	if err != nil {
		if response != nil {
			log.Printf("%+v\n", response.Body)
		}
		log.Printf("%+v\n", response.Body)
		return RunnerInfo{}, err
	}
	return RunnerInfo{
		Name:      name,
		JitConfig: jitConfig.GetEncodedJITConfig(),
	}, nil
}

func isMachineType(label string) bool {
	switch label {
	case "e2-standard-2":
		return true
	case "e2-standard-4":
		return true
	case "e2-standard-8":
		return true
	case "e2-standard-16":
		return true
	case "e2-standard-32":
		return true
	case "e2-highcpu-2":
		return true
	case "e2-highcpu-4":
		return true
	case "e2-highcpu-8":
		return true
	case "e2-highcpu-16":
		return true
	case "e2-highcpu-32":
		return true
	default:
		return false
	}
}

type MachineInfo struct {
	machineType  string
	hasFpgaTools bool
}

func MachineInfoFromLabels(labels []string) (MachineInfo, error) {
	result := MachineInfo{}

	for _, item := range labels {
		if isMachineType(item) {
			if result.machineType != "" {
				return result, fmt.Errorf("multiple machine type labels: %v, %v", result.machineType, item)
			}
			result.machineType = item
		}
		if item == "fpga-tools" {
			result.hasFpgaTools = true
		}
	}
	if result.machineType == "" {
		return result, errors.New("missing machine type label")
	}

	return result, nil
}

// helloHTTP is an HTTP Cloud Function with a request parameter.
func Launch(ctx context.Context, client *github.Client, labels []string) error {
	machineInfo, err := MachineInfoFromLabels(labels)
	if err != nil {
		return err
	}

	runner, err := GitHubRegisterRunner(ctx, client, labels, "")
	if err != nil {
		return err
	}

	instances, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		return err
	}
	disks := singleDisk("global/images/family/github-runner", 16)
	if machineInfo.hasFpgaTools {
		disks = append(disks, &computepb.AttachedDisk{
			Source: proto.String(fmt.Sprintf("zones/%s/disks/fpga-tools", gcpZone)),
			Mode:   proto.String("READ_ONLY"),
		})
	}

	script := strings.ReplaceAll(launchStartupScript, "${JITCONFIG}", runner.JitConfig)

	return createInstanceAndStart(ctx, instances, &computepb.InsertInstanceRequest{
		Project: gcpProject,
		Zone:    gcpZone,
		InstanceResource: &computepb.Instance{
			Name:        proto.String(runner.Name),
			Disks:       disks,
			MachineType: proto.String(fmt.Sprintf("zones/%v/machineTypes/%v", gcpZone, machineInfo.machineType)),
			Metadata: metadata(map[string]string{
				"enable-guest-attributes": "TRUE",
				"serial-port-enable":      "TRUE",
				"startup-script":          script,
			}),
			Labels: map[string]string{
				"gce-github-runner": "",
			},
			NetworkInterfaces: defaultNetworks(),
		},
	})
}
