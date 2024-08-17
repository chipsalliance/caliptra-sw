// Licensed under the Apache-2.0 license

package runner

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/google/go-github/v53/github"
)

func findArtifact(artifacts *github.ArtifactList, name string) (*github.Artifact, error) {
	for _, artifact := range artifacts.Artifacts {
		if artifact.GetName() == name {
			return artifact, nil
		}
	}
	return nil, errors.New("could not find artifact")
}

func DownloadArtifact(ctx context.Context, client *github.Client, workflowFilename string, artifactName string) error {
	repo := "caliptra-sw"
	workflow, _, err := client.Actions.GetWorkflowByFileName(ctx, githubOrg, repo, workflowFilename)
	if err != nil {
		return err
	}
	runs, _, err := client.Actions.ListWorkflowRunsByID(ctx, githubOrg, repo, workflow.GetID(), &github.ListWorkflowRunsOptions{
		Branch: "main",
		Status: "completed",
	})
	if err != nil {
		return err
	}
	if len(runs.WorkflowRuns) == 0 {
		return errors.New("no workflow runs")
	}
	artifacts, _, err := client.Actions.ListWorkflowRunArtifacts(ctx, githubOrg, repo, runs.WorkflowRuns[0].GetID(), &github.ListOptions{})
	if err != nil {
		return err
	}
	artifact, err := findArtifact(artifacts, artifactName)
	if err != nil {
		return err
	}
	url, _, err := client.Actions.DownloadArtifact(ctx, githubOrg, repo, artifact.GetID(), true)
	if err != nil {
		return err
	}
	resp, err := http.Get(url.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Fatalf("Response failed with status code: %d and body %s\n", resp.StatusCode, body)
	}
	_, err = io.Copy(os.Stdout, resp.Body)
	if err != nil {
		return errors.New("unable to copy response body")
	}
	return nil
}
