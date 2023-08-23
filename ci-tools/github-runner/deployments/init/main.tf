
variable "project_id" {
    type = string
}

terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
      version = "4.77.0"
    }
  }
}

resource "google_storage_bucket" "tfstate" {
  project = var.project_id
  name = "${var.project_id}-tfstate"
  force_destroy = false
  location = "US"
  storage_class = "STANDARD"
  versioning {
    enabled = true
  }
  uniform_bucket_level_access = true
}

