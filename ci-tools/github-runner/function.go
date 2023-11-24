// Licensed under the Apache-2.0 license

package runner

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"github.com/GoogleCloudPlatform/functions-framework-go/functions"
	"github.com/google/go-github/v53/github"
	"google.golang.org/protobuf/proto"
)

// Flow:
//
// * GitHub sends job-queued request to github-notify-endpoint
// * github-notify-endpoint asks github for just-in-time runner:
//   https://docs.github.com/en/rest/actions/self-hosted-runners?apiVersion=2022-11-28#create-configuration-for-a-just-in-time-runner-for-an-organization
// *

var gcpZone = envVar("GCP_ZONE")
var gcpProject = envVar("GCP_PROJECT")
var githubOrg = envVar("GITHUB_ORG")

const imageBuilderInstanceName = "github-runner-image-builder"

func envVar(name string) string {
	val, found := os.LookupEnv(name)
	if !found || val == "" {
		panic(fmt.Sprintf("Environment variable %v not found", name))
	}
	return val
}

func init() {
	functions.HTTP("RunnerCleanup", handleCleanup)
	functions.HTTP("RunnerLaunch", handleLaunch)
	functions.HTTP("RunnerBuildImage", handleBuildImage)
}

func readAppId() (int64, error) {
	env, found := os.LookupEnv("GITHUB_APP_ID")
	if !found {
		return 0, fmt.Errorf("environment variable GITHUB_APP_ID not set")
	}
	return strconv.ParseInt(env, 10, 64)
}
func handleCleanup(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	err := Cleanup(ctx)
	if err != nil {
		log.Printf("Cleanup error: %v\n", err)
		http.Error(w, "", http.StatusInternalServerError)
	}
}

func handleLaunch(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Must be POST", http.StatusBadRequest)
		return
	}
	appID, err := readAppId()
	if err != nil {
		log.Printf("Error reading app id: %v\n", err)
		http.Error(w, "", http.StatusInternalServerError)
		return

	}
	secretToken, err := os.ReadFile("/etc/secrets/caliptra-gce-ci-github-webhook-secret-txt/latest")
	if err != nil {
		log.Printf("Error reading webhook secret: %v\n", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	payload, err := github.ValidatePayload(r, secretToken)
	if err != nil {
		log.Printf("Error validating payload: %v\n", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	log.Println(string(payload))
	event, err := github.ParseWebHook(github.WebHookType(r), payload)
	if err != nil {
		log.Printf("Error parsing webhook: %v\n", err)
		http.Error(w, "", http.StatusInternalServerError)
	}
	log.Printf("%+v\n", event)
	ctx := context.Background()
	switch event := event.(type) {
	case *github.WorkflowJobEvent:
		if event.GetAction() == "queued" {
			labels := event.GetWorkflowJob().Labels
			_, err := MachineInfoFromLabels(labels)
			if err != nil {
				log.Printf("Job doesn't have a label we care about: %v\n", err)
				return
			}
			installation := event.GetInstallation()
			log.Printf("Launching runner job %v\n", installation)
			client, err := GithubClient(appID, installation.GetID())
			if err != nil {
				log.Printf("Error: %v\n", err)
				http.Error(w, "", http.StatusInternalServerError)
				return
			}

			err = Launch(ctx, client, labels)
			if err != nil {
				log.Printf("Error: %v\n", err)
				http.Error(w, "", http.StatusInternalServerError)
				return
			}
		}
	}
}
func handleBuildImage(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	err := BuildImage(ctx)
	if err != nil {
		log.Printf("Error: %v\n", err)
		http.Error(w, "", http.StatusInternalServerError)
	}
}

func singleDisk(image string, size int64) []*computepb.AttachedDisk {
	return []*computepb.AttachedDisk{
		{
			InitializeParams: &computepb.AttachedDiskInitializeParams{
				DiskSizeGb:  proto.Int64(size),
				SourceImage: proto.String(image),
				DiskType: proto.String(
					fmt.Sprintf("https://www.googleapis.com/compute/v1/projects/%v/zones/%v/diskTypes/pd-ssd", gcpProject, gcpZone)),
			},
			AutoDelete: proto.Bool(true),
			Boot:       proto.Bool(true),
			Type:       proto.String(computepb.AttachedDisk_PERSISTENT.String()),
		},
	}
}

func metadata(kv map[string]string) *computepb.Metadata {
	result := computepb.Metadata{}
	keys := []string{}
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		result.Items = append(result.Items, &computepb.Items{
			Key:   proto.String(k),
			Value: proto.String(kv[k]),
		})
	}
	return &result
}

func createInstanceAndStart(ctx context.Context, instances *compute.InstancesClient, req *computepb.InsertInstanceRequest) error {
	log.Printf("Creating VM instance %v\n", req.GetInstanceResource().GetName())
	op, err := instances.Insert(ctx, req)
	if err != nil {
		return err
	}
	err = op.Wait(ctx)
	if err != nil {
		return err
	}
	log.Printf("Starting VM instance %v\n", req.GetInstanceResource().GetName())
	op, err = instances.Start(ctx, &computepb.StartInstanceRequest{
		Project:  req.Project,
		Zone:     req.Zone,
		Instance: *req.InstanceResource.Name,
	})
	if err != nil {
		instanceDelete(ctx, instances, req.InstanceResource.GetName())
		return err
	}
	err = op.Wait(ctx)
	if err != nil {
		instanceDelete(ctx, instances, req.InstanceResource.GetName())
		return err
	}
	return nil
}

func instanceDelete(ctx context.Context, instances *compute.InstancesClient, name string) error {
	log.Printf("Deleting VM %v\n", name)
	op, err := instances.Delete(ctx, &computepb.DeleteInstanceRequest{
		Project:  gcpProject,
		Zone:     gcpZone,
		Instance: name,
	})
	if err != nil {
		log.Printf("Unable to delete %v VM: %v\n", name, err)
		return err
	}
	err = op.Wait(ctx)
	if err != nil {
		log.Printf("Unable to delete %v VM: %v\n", name, err)
		return err
	}
	return nil
}

func instanceState(ctx context.Context, instances *compute.InstancesClient, name string) (*computepb.Instance, error) {
	result, err := instances.Get(ctx, &computepb.GetInstanceRequest{
		Project:  gcpProject,
		Zone:     gcpZone,
		Instance: name,
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func findItem(items []*computepb.GuestAttributesEntry, name string) string {
	for _, item := range items {
		if item.GetKey() == name {
			return item.GetValue()
		}
	}
	return ""
}

type serialCollector struct {
	next int64
}

func (s *serialCollector) printLatest(ctx context.Context, instances *compute.InstancesClient) {
	r, err := instances.GetSerialPortOutput(ctx, &computepb.GetSerialPortOutputInstanceRequest{
		Project:  gcpProject,
		Zone:     gcpZone,
		Instance: imageBuilderInstanceName,
		Port:     proto.Int32(1),
		Start:    proto.Int64(s.next),
	})
	if err != nil {
		return
	}
	fmt.Print(r.GetContents())
	s.next = r.GetNext()
}

func defaultNetworks() []*computepb.NetworkInterface {
	return []*computepb.NetworkInterface{
		{
			Name: proto.String("global/networks/default"),
			AccessConfigs: []*computepb.AccessConfig{
				{
					Type: proto.String("ONE_TO_ONE_NAT"),
					Name: proto.String("The Internet"),
				},
			},
		},
	}
}
