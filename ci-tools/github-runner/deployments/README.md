# Setup GitHub App

* Visit `https://github.com/organizations/ORG_NAME_HERE/settings/apps`,
  replacing ORG_NAME_HERE with your organization's name.

* Click "New GitHub app", and give the app a name, perhaps something like "GHA
  runners on GCP". To help people understand what this is, set the "Homepage
  URL" to https://github.com/chipsalliance/caliptra-sw/tree/main/ci-tools/github-runner

* Uncheck the Webhook "Active" check-box. Once the project is fully deployed we
  will fill in the callback URL later.
  
* Generate a random string and put it in the "Webhook secret" section. We will
  need to store this string later in the GCP secret manager.

* In "Repository Permissions, select the following:

  * Actions - "Read-only"
  * Metadata - "Read-only"
  * Set everything else to "No access"

* In Organization Permissions

  * Self-hosted runners: "Read and Write"

* Under "Subscribe to events", check the following

  * Meta
  * Workflow job

* Under "Where can this GitHub App be installed", select "Only on this account"

* Press "Create GibHub App"

* Scroll down to "Private keys", and press "Generate a private key", and keep
  the downloaded file to be uploaded into the GCP Secret Manager later.

* Click on "App managers". Add any users you trust to manage this app for you.

* Click on "Install App"

* Select "Only select repositories"

* Choose the repos that want to use these test runners.

* Click Install

Prod app is https://github.com/organizations/chipsalliance/settings/apps/caliptra-gha-runners-on-gcp
 
# Setup application-default permissions

This creates temporary credentials terraform can use to access your account:

```
gcloud auth application-default login
```

# Initial project setup

First, create files similar to deployments/env/kor.tfvars and
deployments/env/kor.tfbackend for your environment-specific settings, and set
the `ENV_NAME` environment variable to your basename before running the commands
below. Copy the GitHub App ID from your GitHub App.

Next, we need to setup the bucket used for the main tfstate.

```
cd deployments/init
terraform init -var-file=../env/${ENV_NAME}.tfvars
terraform apply -var-file=../env/${ENV_NAME}.tfvars -state=${ENV_NAME}.tfstate
```

Next, let's initialize the main deployment directory:

```
cd deployments/
terraform init -var-file=env/${ENV_NAME}.tfvars -backend-config=env/${ENV_NAME}.tfbackend
```

Next, let's create the secrets (we can't create the cloud functions yet until we
manually populate the secrets).

caliptra-gce-ci-github-private-key-pem is your GitHub App's private key

caliptra-gce-ci-github-webhook-secret-txt is your Githb App's webhook secret

```
terraform apply -var-file=env/${ENV_NAME}.tfvars \
    -target 'google_secret_manager_secret.github_webhook' \
    -target 'google_secret_manager_secret.github_private_key' 
gcloud --project $PROJECT secrets versions add \
    caliptra-gce-ci-github-private-key-pem --data-file path/to/private-key-pem
gcloud --project $PROJECT secrets versions add \
    caliptra-gce-ci-github-webhook-secret-txt --data-file path/to/secret
```

Now, we can deploy everything:

```
terraform apply -var-file=env/${ENV_NAME}.tfvars
```

Terraform will print out the runner_launch_uri. Copy this to the WebHook
URL in the GitHub App settings and enable "Active".

# Deploying changes

After making changes to the terraform scripts and/or cloud functions, you can
deploy those changes like this:

```
$ terraform apply -var-file=env/${ENV_NAME}.tfvars
```

# Build the initial runner image

Normally, the automation will rebuild the runner image every sunday. However, we
need to manually create the first one.

* Visit https://console.cloud.google.com/cloudscheduler

* Select your project from the select-box in the top-left corner

* Find the "runner-build-image" scheduler job, click the ... menu at the
  right side of the row, and select "Force Run".

* It may take some time for IAM changes to fully deploy, so if you get a
  permission-denied error soon after deploying the project for the first time,
  try again in a few minutes.


# Debugging

* Visit https://console.cloud.corp.google.com/functions/list?project=YOUR_PROJECT

* Click on the function name you're interested in. Usually runner-launch (called
  by the GitHub webhook) or runner-build-image (scheduled or ran manually).

* Visit the logs tab, which will included details information about what the
  function is doing. The runner-build-image task will write the serial output
  for any VM it launches there, which is useful for debugging problems with the
  installation scripts.
