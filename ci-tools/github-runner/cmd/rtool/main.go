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
	fmt.Println("Usage: this_cmd [launch|serve|build_image|cleanup|jitconfig]")
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
			runner, err := hello.GitHubRegisterRunner(ctx, client, labels)
			if err == nil {
				log.Println(runner.JitConfig)
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
		log.Println(jitConfig)
	} else {
		usage()
		os.Exit(1)
	}
}
