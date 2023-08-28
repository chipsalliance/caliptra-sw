// Licensed under the Apache-2.0 license

package runner

import (
	"context"
	"fmt"
	"log"

	pubsub "cloud.google.com/go/pubsub/apiv1"
	"cloud.google.com/go/pubsub/apiv1/pubsubpb"
	"github.com/google/go-github/v53/github"
)

func PublishJitConfig(ctx context.Context, client *github.Client, labels []string) error {
	runner, err := GitHubRegisterRunner(ctx, client, labels)
	if err != nil {
		return err
	}
	log.Println(runner.JitConfig)
	pubsubClient, err := pubsub.NewPublisherRESTClient(ctx)
	if err != nil {
		return err
	}
	defer pubsubClient.Close()
	fmt.Println("Publish")
	_, err = pubsubClient.Publish(ctx, &pubsubpb.PublishRequest{
		Topic: fmt.Sprintf("projects/%v/topics/hw-runner-requests", gcpProject),
		Messages: []*pubsubpb.PubsubMessage{
			{
				Data: []byte(runner.JitConfig),
			},
		},
	})
	return err
}

func ReceiveJitConfig(ctx context.Context) (string, error) {
	pubsubClient, err := pubsub.NewSubscriberRESTClient(ctx)
	if err != nil {
		return "", err
	}
	defer pubsubClient.Close()

	subscription := fmt.Sprintf("projects/%v/subscriptions/hw-runner-requests", gcpProject)
	for {
		log.Println("Pull")
		res, err := pubsubClient.Pull(ctx, &pubsubpb.PullRequest{
			Subscription: subscription,
			MaxMessages:  1,
		})
		if err != nil {
			return "", err
		}
		count := len(res.GetReceivedMessages())
		if count == 1 {
			msg := res.GetReceivedMessages()[0]
			err = pubsubClient.Acknowledge(ctx, &pubsubpb.AcknowledgeRequest{
				Subscription: subscription,
				AckIds: []string{
					msg.GetAckId(),
				},
			})
			if err != nil {
				return "", fmt.Errorf("acknowledge failed %v", err)
			}
			return string(msg.GetMessage().GetData()), nil
		}
		if count > 1 {
			return "", fmt.Errorf("unexpected number of messages: %v", count)
		}
	}
}
