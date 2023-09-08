// Licensed under the Apache-2.0 license

package runner

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
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

func GitHubRegisterRunner(ctx context.Context, client *github.Client, machineTypeLabel string) (RunnerInfo, error) {
	name := fmt.Sprintf("gce-github-runner-%v", randId())
	jitConfig, response, err := client.Actions.GenerateOrgJITConfig(ctx, githubOrg, &github.GenerateJITConfigRequest{
		Name:          name,
		RunnerGroupID: 1,
		Labels: []string{
			machineTypeLabel,
		},
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

// helloHTTP is an HTTP Cloud Function with a request parameter.
func Launch(ctx context.Context, client *github.Client, machineTypeLabel string) error {
	runner, err := GitHubRegisterRunner(ctx, client, machineTypeLabel)
	if err != nil {
		return err
	}

	instances, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		return err
	}
	disks := singleDisk("global/images/family/github-runner", 16)

	script := strings.ReplaceAll(launchStartupScript, "${JITCONFIG}", runner.JitConfig)

	return createInstanceAndStart(ctx, instances, &computepb.InsertInstanceRequest{
		Project: gcpProject,
		Zone:    gcpZone,
		InstanceResource: &computepb.Instance{
			Name:        proto.String(runner.Name),
			Disks:       disks,
			MachineType: proto.String(fmt.Sprintf("zones/%v/machineTypes/%v", gcpZone, machineTypeLabel)),
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
