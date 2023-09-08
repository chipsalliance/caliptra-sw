

variable "region" {
  type = string
}

variable "zone" {
  type = string
}

variable "project_id" {
  type = string
}

variable "github_app_id" {
  type = number
}

variable "github_org" {
  type = string
}

locals {
  cf_env_vars = {
    GCP_ZONE    = var.zone
    GCP_REGION  = var.region
    GCP_PROJECT = var.project_id
    GITHUB_APP_ID = var.github_app_id
    GITHUB_ORG = var.github_org
  }
}

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "4.77.0"
    }
  }
  backend "gcs" {
    prefix = "terraform/state"
  }
}

//////////////// Service accounts

resource "google_service_account" "vm_maintenance_scheduler" {
  account_id = "vm-maintenance-scheduler"
}
resource "google_service_account" "vm_creator" {
  account_id = "vm-creator"
}
// Delete the cruft
resource "google_project_default_service_accounts" "delete_default_service_accounts" {
  project = var.project_id
  action  = "DELETE"
}

provider "google" {
  project = var.project_id
}

resource "google_project_service" "enabled_apis" {
  for_each = toset([
    "cloudbuild.googleapis.com",
    "cloudfunctions.googleapis.com",
    "cloudscheduler.googleapis.com",
    "compute.googleapis.com",
    "run.googleapis.com",
    "secretmanager.googleapis.com",
  ])
  project = var.project_id
  service = each.key
}

//////////////// Secrets

// To avoid leaking the secret contents in tfstate, the secret "version"
// must be manually deployed with "gcloud secrets add"

resource "google_secret_manager_secret" "github_webhook" {
  secret_id = "caliptra-gce-ci-github-webhook-secret-txt"
  replication {
    automatic = true
  }
  depends_on = [google_project_service.enabled_apis]
}
resource "google_secret_manager_secret" "github_private_key" {
  secret_id = "caliptra-gce-ci-github-private-key-pem"
  replication {
    automatic = true
  }
  depends_on = [google_project_service.enabled_apis]
}

// To avoid leaking the secret contents in tfstate, the secret "version"
// must be manually deployed

//////////////// Cloud Functions Source Code

resource "random_uuid" "cf_upload_bucket_suffix" {
}
resource "google_storage_bucket" "cf_upload_bucket" {
  project                     = var.project_id
  name                        = "cf-uploads-${random_uuid.cf_upload_bucket_suffix.result}"
  location                    = var.region
  force_destroy               = true
  uniform_bucket_level_access = true

  lifecycle_rule {
    condition {
      age = 1
    }
    action {
      type = "Delete"
    }
  }
}
data "archive_file" "cf_source_archive" {
  type        = "zip"
  output_path = "artifacts/cf_source.zip"
  source_dir  = "../"
  excludes = [
    "deployments",
    "cmd",
  ]
}
resource "google_storage_bucket_object" "cf_upload_object" {
  name   = "cf_source-${data.archive_file.cf_source_archive.output_sha256}.zip"
  bucket = google_storage_bucket.cf_upload_bucket.name
  source = data.archive_file.cf_source_archive.output_path

}

//////////////// Cloud Functions Deployment

// Builds a VM image for runners to use.
resource "google_cloudfunctions2_function" "runner_build_image" {
  name     = "runner-build-image"
  location = var.region

  build_config {
    runtime     = "go120"
    entry_point = "RunnerBuildImage"
    source {
      storage_source {
        bucket = google_storage_bucket.cf_upload_bucket.name
        object = google_storage_bucket_object.cf_upload_object.name
      }
    }
  }

  service_config {
    available_memory      = "256M"
    service_account_email = google_service_account.vm_creator.email
    environment_variables = local.cf_env_vars
    timeout_seconds       = 1200
  }
  depends_on = [
    google_project_service.enabled_apis,
    google_project_iam_binding.project_artifactregister_reader
  ]
}

// Called by Github App webhook, launches runner if necessary.
resource "google_cloudfunctions2_function" "runner_launch" {
  name     = "runner-launch"
  location = var.region

  build_config {
    runtime     = "go120"
    entry_point = "RunnerLaunch"
    source {
      storage_source {
        bucket = google_storage_bucket.cf_upload_bucket.name
        object = google_storage_bucket_object.cf_upload_object.name
      }
    }
  }

  service_config {
    available_memory      = "256M"
    service_account_email = google_service_account.vm_creator.email
    environment_variables = local.cf_env_vars
    timeout_seconds       = 300

    secret_volumes {
      mount_path = "/etc/secrets/${google_secret_manager_secret.github_webhook.secret_id}"
      project_id = var.project_id
      secret     = google_secret_manager_secret.github_webhook.secret_id
      versions {
        version = "latest"
        path = "latest"
      }
    }
    secret_volumes {
      mount_path = "/etc/secrets/${google_secret_manager_secret.github_private_key.secret_id}"
      project_id = var.project_id
      secret     = google_secret_manager_secret.github_private_key.secret_id
      versions {
        version = "latest"
        path = "latest"
      }
    }
  }
  depends_on = [
    google_project_service.enabled_apis,
    google_project_iam_binding.project_artifactregister_reader
  ]
}

// Deletes any stopped or stuck vms.
resource "google_cloudfunctions2_function" "runner_cleanup" {
  name     = "runner-cleanup"
  location = var.region

  build_config {
    runtime     = "go120"
    entry_point = "RunnerCleanup"
    source {
      storage_source {
        bucket = google_storage_bucket.cf_upload_bucket.name
        object = google_storage_bucket_object.cf_upload_object.name
      }
    }
  }
  service_config {
    available_memory      = "256M"
    service_account_email = google_service_account.vm_creator.email
    environment_variables = local.cf_env_vars
    timeout_seconds       = 300
  }
  depends_on = [
    google_project_service.enabled_apis,
    google_project_iam_binding.project_artifactregister_reader
  ]
}

//////////////// Scheduler

resource "google_cloud_scheduler_job" "runner_build_image" {
  name        = "runner-build-image"
  description = "Schedule the HTTPS trigger for runner-build-image cloud function"
  schedule    = "44 1 * * 1" # Monday at 01:44
  project     = google_cloudfunctions2_function.runner_build_image.project
  region      = google_cloudfunctions2_function.runner_build_image.location

  attempt_deadline = format("%ss", google_cloudfunctions2_function.runner_build_image.service_config[0].timeout_seconds + 30)

  http_target {
    uri         = google_cloudfunctions2_function.runner_build_image.service_config[0].uri
    http_method = "POST"
    oidc_token {
      audience              = "${google_cloudfunctions2_function.runner_build_image.service_config[0].uri}/"
      service_account_email = google_service_account.vm_maintenance_scheduler.email
    }
  }
}

resource "google_cloud_scheduler_job" "runner_cleanup" {
  name        = "runner-cleanup"
  description = "Schedule the HTTPS trigger for runner-cleanup cloud function"
  schedule    = "*/10 * * * *" # every 10 minutes
  project     = google_cloudfunctions2_function.runner_cleanup.project
  region      = google_cloudfunctions2_function.runner_cleanup.location

  attempt_deadline = format("%ss", google_cloudfunctions2_function.runner_cleanup.service_config[0].timeout_seconds + 30)

  http_target {
    uri         = google_cloudfunctions2_function.runner_cleanup.service_config[0].uri
    http_method = "POST"
    oidc_token {
      audience              = "${google_cloudfunctions2_function.runner_cleanup.service_config[0].uri}/"
      service_account_email = google_service_account.vm_maintenance_scheduler.email
    }
  }
}

//////////////// Hardware runners

locals {
  hw_runners = toset([
    "kor0",
    "kor1",
  ])
}

resource "google_pubsub_topic" "hw_runner_requests" {
  name                       = "hw-runner-requests"
  message_retention_duration = "3600s"
}

resource "google_pubsub_subscription" "hw_runner_requests" {
  name  = google_pubsub_topic.hw_runner_requests.name
  topic = google_pubsub_topic.hw_runner_requests.name

  ack_deadline_seconds       = 20
  retain_acked_messages      = false
  message_retention_duration = "3600s"
  expiration_policy {
    ttl = ""
  }
  enable_exactly_once_delivery = true
}

resource "google_service_account" "hw_runners" {
  for_each   = local.hw_runners
  account_id = "hw-runner-${each.key}"
}

//////////////// IAM Bindings

resource "google_pubsub_topic_iam_binding" "hw_runner_requests" {
  role    = "roles/pubsub.publisher"
  project = var.project_id
  topic   = google_pubsub_topic.hw_runner_requests.name
  members = [
    "serviceAccount:${google_service_account.vm_creator.email}",
  ]
}

resource "google_pubsub_subscription_iam_binding" "hw_runner_requests" {
  role         = "roles/pubsub.subscriber"
  project      = var.project_id
  subscription = google_pubsub_subscription.hw_runner_requests.name
  members      = [for r in google_service_account.hw_runners : "serviceAccount:${r.email}"]
}

resource "google_project_iam_binding" "project_artifactregister_reader" {
  project = var.project_id
  role    = "roles/artifactregistry.reader"
  members = [
    "serviceAccount:${google_service_account.vm_creator.email}",
    "serviceAccount:${google_service_account.vm_maintenance_scheduler.email}",
  ]
}
resource "google_project_iam_binding" "project_compute_instanceadmin" {
  project = var.project_id
  role    = "roles/compute.instanceAdmin.v1"
  members = [
    "serviceAccount:${google_service_account.vm_creator.email}",
  ]
}
resource "google_secret_manager_secret_iam_binding" "github_webhook" {
  secret_id = google_secret_manager_secret.github_webhook.secret_id
  role      = "roles/secretmanager.secretAccessor"
  members = [
    "serviceAccount:${google_service_account.vm_creator.email}",
  ]
}
resource "google_secret_manager_secret_iam_binding" "github_private_key" {
  secret_id = google_secret_manager_secret.github_private_key.secret_id
  role      = "roles/secretmanager.secretAccessor"
  members = [
    "serviceAccount:${google_service_account.vm_creator.email}",
  ]
}
resource "google_cloudfunctions2_function_iam_binding" "runner_cleanup_invoker" {
  location       = google_cloudfunctions2_function.runner_cleanup.location
  cloud_function = google_cloudfunctions2_function.runner_cleanup.name
  role           = "roles/cloudfunctions.invoker"
  members = [
    "serviceAccount:${google_service_account.vm_maintenance_scheduler.email}",
  ]
}
resource "google_cloudfunctions2_function_iam_binding" "runner_build_image_invoker" {
  location       = google_cloudfunctions2_function.runner_build_image.location
  cloud_function = google_cloudfunctions2_function.runner_build_image.name
  role           = "roles/cloudfunctions.invoker"
  members = [
    "serviceAccount:${google_service_account.vm_maintenance_scheduler.email}",
  ]
}
resource "google_cloud_run_service_iam_binding" "runner_cleanup_invoker" {
  location = google_cloudfunctions2_function.runner_cleanup.location
  service  = google_cloudfunctions2_function.runner_cleanup.name
  role     = "roles/run.invoker"
  members = [
    "serviceAccount:${google_service_account.vm_maintenance_scheduler.email}",
  ]
}
resource "google_cloud_run_service_iam_binding" "runner_build_image_invoker" {
  location = google_cloudfunctions2_function.runner_build_image.location
  service  = google_cloudfunctions2_function.runner_build_image.name
  role     = "roles/run.invoker"
  members = [
    "serviceAccount:${google_service_account.vm_maintenance_scheduler.email}",
  ]
}

// Github doesn't call with any IAM creds; function is responsible for verifying
// identity using the webhook secret instead
resource "google_cloud_run_v2_service_iam_binding" "runner_launch" {
  location = google_cloudfunctions2_function.runner_launch.location
  name     = google_cloudfunctions2_function.runner_launch.name

  role = "roles/run.invoker"
  members = [
    "allUsers"
  ]
}

output "runner_launch_uri" {
  value = google_cloudfunctions2_function.runner_launch.service_config[0].uri
}
