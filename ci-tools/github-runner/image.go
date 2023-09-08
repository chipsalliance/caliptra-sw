// Licensed under the Apache-2.0 license

package runner

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"time"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/protobuf/proto"
)

//go:embed scripts/tweak_runner_image.sh
var tweak_runner_image_script string

const baseImage = "projects/ubuntu-os-cloud/global/images/family/ubuntu-2204-lts"

func BuildImage(ctx context.Context) error {
	instances, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		return err
	}
	defer instances.Close()
	snapshotsClient, err := compute.NewSnapshotsRESTClient(ctx)
	if err != nil {
		return err
	}
	defer snapshotsClient.Close()
	disksClient, err := compute.NewDisksRESTClient(ctx)
	if err != nil {
		return err
	}
	defer disksClient.Close()
	imagesClient, err := compute.NewImagesRESTClient(ctx)
	if err != nil {
		return err
	}
	defer imagesClient.Close()

	disks := singleDisk(baseImage, 16)

	err = createInstanceAndStart(ctx, instances, &computepb.InsertInstanceRequest{
		Project: gcpProject,
		Zone:    gcpZone,
		InstanceResource: &computepb.Instance{
			Name:  proto.String(imageBuilderInstanceName),
			Disks: disks,
			MachineType: proto.String(
				fmt.Sprintf("zones/%v/machineTypes/e2-highcpu-32", gcpZone)),
			Metadata: metadata(map[string]string{
				"enable-guest-attributes": "TRUE",
				"serial-port-enable":      "TRUE",
				"startup-script":          tweak_runner_image_script,
			}),
			NetworkInterfaces: defaultNetworks(),
		},
	})
	if err != nil {
		return err
	}
	defer instanceDelete(ctx, instances, imageBuilderInstanceName)

	serial := serialCollector{}
	var state *computepb.Instance
	for {
		state, err = instanceState(ctx, instances, imageBuilderInstanceName)
		if err != nil {
			log.Printf("Error getting instance state: %v\n", err)
			return err
		}
		serial.printLatest(ctx, instances)

		if state.GetStatus() == "TERMINATED" {
			break
		}
		time.Sleep(10 * time.Second)
	}
	log.Printf("VM %v has terminated\n", imageBuilderInstanceName)

	attr, err := instances.GetGuestAttributes(ctx, &computepb.GetGuestAttributesInstanceRequest{
		Zone:      gcpZone,
		Project:   gcpProject,
		Instance:  imageBuilderInstanceName,
		QueryPath: proto.String("caliptra-github-ci/startup-script-result"),
	})
	if err != nil {
		return err
	}
	startupScriptResult := findItem(attr.GetQueryValue().GetItems(), "startup-script-result")
	if startupScriptResult != "SUCCESS" {
		log.Printf("startup script failed with result %q\n", startupScriptResult)
		return fmt.Errorf("startup script failed")
	}
	disk, err := disksClient.Get(ctx, &computepb.GetDiskRequest{
		Project: gcpProject,
		Zone:    gcpZone,
		Disk:    imageBuilderInstanceName,
	})
	if err != nil {
		return err
	}

	now := time.Now()
	versionSuffix := now.Format("200601021504")

	log.Println("Creating Image")
	op, err := imagesClient.Insert(ctx, &computepb.InsertImageRequest{
		Project:     gcpProject,
		ForceCreate: proto.Bool(true),
		ImageResource: &computepb.Image{
			Name:       proto.String(fmt.Sprintf("github-runner-%v", versionSuffix)),
			SourceDisk: proto.String(disk.GetSelfLink()),
			Family:     proto.String("github-runner"),
			Labels: map[string]string{
				"gce-github-runner": "",
			},
		},
	})
	if err != nil {
		return err
	}
	err = op.Wait(ctx)
	if err != nil {
		return err
	}

	return nil
}
