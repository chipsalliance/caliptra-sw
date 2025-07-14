// Licensed under the Apache-2.0 license

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	// Blank-import the function package so the init() runs
	hello "caliptra.org/github-runner"
	"github.com/GoogleCloudPlatform/functions-framework-go/funcframework"
)

func usage() {
	fmt.Println(`Usage: rtool [launch|serve|build_image|cleanup|jitconfig|download_artifact] [...]

  download_artifact <app_id> <installation_id> <workflow_filename> <artifact_name> <branch>

    Download an artifact from Github. A cronjob on the fpga_boss machine
    can use this command to download the latest output of the "Build FPGA SD
    image" workflow, which fpga_boss will flash the FPGAs with between every
    job.

  launch <machine_types_csv> <app_id> <installation_id>

    Launch a GCE VM of the specified machine-type and give it new just-in-time
    GHA runner creds. This is typically used for testing logic used by the GCF
    locally.

  jitconfig <machine_types_csv> <app_id> <installation_id> <runner_name>

    Register a new GHA just-in-time runner and return the jitconfig. This can
    be used with "fpga_boss serve" to get a fresh jitconfig for an FPGA if you
    have app credentials.

  receive_jitconfig

    Pull a jitconfig from the GCP queue; may block if none is available.

  publish_jitconfig <machine_types_csv> <app_id> <installation_id>

    Generate a new jitconfig and put it into the GCP queue; for testing only.

  serve

    Launch a webserver locally to serve the cloud functions. Can be useful for testing.

  cleanup

    Cleanup old or stuck GCE VMs. Mostly used for testing GCF logic.

  build_image

    Launch a GCE VM to build a fresh GitHub Runner image with all the latest
    security fixes. Mostly used for testing GCF logic.

  Common arguments:

    app_id: The Github app_id to use. This is typically 379559 (the [Caliptra]
            GHA-runners-on-GCP app)

    installation_id: The installation id of the app
`)
}

func main() {
	if len(os.Args) <= 1 {
		usage()
		os.Exit(1)
	}
	ctx := context.Background()
	if os.Args[1] == "serve" {
		// Use PORT environment variable, or default to 8080.
		port := "8080"
		if envPort := os.Getenv("PORT"); envPort != "" {
			port = envPort
		}
		if err := funcframework.Start(port); err != nil {
			log.Fatalf("funcframework.Start: %v\n", err)
		}
	} else if os.Args[1] == "cleanup" {
		err := hello.Cleanup(ctx)
		if err != nil {
			log.Fatal(err)
		}

	} else if os.Args[1] == "build_image" {
		err := hello.BuildImage(ctx)
		if err != nil {
			log.Fatal(err)
		}
	} else if os.Args[1] == "download_artifact" {
		appId, err := strconv.ParseInt(os.Args[2], 10, 64)
		if err != nil {
			log.Fatal(err)
		}
		installationId, err := strconv.ParseInt(os.Args[3], 10, 64)
		if err != nil {
			log.Fatal(err)
		}
		client, err := hello.GithubClient(appId, installationId)
		if err != nil {
			log.Fatal(err)
		}
		err = hello.DownloadArtifact(ctx, client, os.Args[4], os.Args[5], os.Args[6])
		if err != nil {
			log.Fatal(err)
		}
		return
	} else if os.Args[1] == "launch" || os.Args[1] == "jitconfig" || os.Args[1] == "publish_jitconfig" {
		if len(os.Args) <= 4 {
			log.Fatalf("usage: this_cmd launch <machine_type> <app_id> <installation_id>")
		}
		appId, err := strconv.ParseInt(os.Args[3], 10, 64)
		if err != nil {
			log.Fatal(err)
		}
		installationId, err := strconv.ParseInt(os.Args[4], 10, 64)
		if err != nil {
			log.Fatal(err)
		}
		client, err := hello.GithubClient(appId, installationId)
		if err != nil {
			log.Fatal(err)
		}
		labels := strings.Split(os.Args[2], ",")
		if os.Args[1] == "launch" {
			err = hello.Launch(ctx, client, labels)
		} else if os.Args[1] == "publish_jitconfig" {
			err = hello.PublishJitConfig(ctx, client, labels)
		} else {
			runner, err := hello.GitHubRegisterRunner(ctx, client, labels, os.Args[5])
			if err == nil {
				fmt.Println(runner.JitConfig)
			} else {
				log.Fatal(err)
			}
		}
		if err != nil {
			log.Fatal(err)
		}
	} else if os.Args[1] == "receive_jitconfig" {
		jitConfig, err := hello.ReceiveJitConfig(ctx)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(jitConfig)
	} else {
		usage()
		os.Exit(1)
	}
}
