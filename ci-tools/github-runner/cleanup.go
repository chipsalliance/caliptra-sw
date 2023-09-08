// Licensed under the Apache-2.0 license

package runner

import (
	"context"
	"log"
	"sort"
	"time"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/api/iterator"
	"google.golang.org/protobuf/proto"
)

const maxVmDuration = 12 * time.Hour

func cleanupInstances(ctx context.Context) error {
	instanceSvc, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		return err
	}
	log.Printf("Cleanup Instances\n")
	instances := instanceSvc.List(ctx, &computepb.ListInstancesRequest{
		Zone:    gcpZone,
		Project: gcpProject,
		Filter:  proto.String("labels.gce-github-runner:* OR name=github-runner-image-builder"),
	})
	for {
		instance, err := instances.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return err
		}
		creationTime, err := time.Parse(time.RFC3339, instance.GetCreationTimestamp())
		if err != nil {
			log.Printf("Error parsing vm creation time: %v", err)
			continue
		}
		_, is_runner := instance.Labels["gce-github-runner"]
		if !is_runner && instance.GetName() != "github-runner-image-builder" {
			log.Printf("filter returned an unexpected instance: %v", instance.GetName())
			continue
		}
		instanceTooOld := creationTime.Add(maxVmDuration).Before(time.Now())

		if instance.GetStatus() == "TERMINATED" || instanceTooOld {
			log.Printf("Deleting instance %v", instance.GetName())
			instanceSvc.Delete(ctx, &computepb.DeleteInstanceRequest{
				Zone:     gcpZone,
				Project:  gcpProject,
				Instance: instance.GetName(),
			})
		}
	}
	return nil
}

func cleanupImages(ctx context.Context) error {
	imageSvc, err := compute.NewImagesRESTClient(ctx)
	if err != nil {
		return err
	}
	log.Printf("Cleanup Images\n")
	iter := imageSvc.List(ctx, &computepb.ListImagesRequest{
		Project: gcpProject,
		Filter:  proto.String("labels.gce-github-runner:*"),
	})
	count := 0
	images := []string{}
	for {
		log.Printf("Calling next")
		image, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return err
		}
		images = append(images, image.GetName())
		count++
	}
	sort.Sort(sort.Reverse(sort.StringSlice(images)))
	for i, image := range images {
		// Only keep the most recent 3 images
		if i >= 3 {
			imageSvc.Delete(ctx, &computepb.DeleteImageRequest{
				Project: gcpProject,
				Image:   image,
			})
		}
	}
	return nil
}

func Cleanup(ctx context.Context) error {
	err := cleanupInstances(ctx)
	if err != nil {
		return err
	}

	return cleanupImages(ctx)
}
