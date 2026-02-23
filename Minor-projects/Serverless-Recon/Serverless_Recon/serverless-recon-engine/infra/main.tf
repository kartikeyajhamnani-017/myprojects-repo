provider "google" {
  project = var.project_id
  region  = var.region
}

# -----------------------------------------------------------------------------
# 1. The Event Bus (Pub/Sub)
# -----------------------------------------------------------------------------
resource "google_pubsub_topic" "recon_topic" {
  name = "recon-topic"

  # Senior Note: We enable message retention so we don't lose events 
  # if the consumer (Function) is down for maintenance.
  message_retention_duration = "86600s" # 1 day + buffer
}

# -----------------------------------------------------------------------------
# 2. The Honeypot Storage (GCS)
# -----------------------------------------------------------------------------
resource "google_storage_bucket" "honeypot_bucket" {
  # Bucket names must be globally unique. We append the project ID to ensure uniqueness.
  name          = "${var.project_id}-honeypot-logs"
  location      = var.region
  force_destroy = true # Allows terraform to delete the bucket even if it has files (Safe for Dev)

  uniform_bucket_level_access = true # Security Best Practice
}

# -----------------------------------------------------------------------------
# 3. The "Hidden" IAM Permission (The Glue)
# -----------------------------------------------------------------------------
# Critical: Google Storage is its own entity. It needs permission to "Publish" 
# to your topic. Without this, the notification will silently fail.

data "google_storage_project_service_account" "gcs_account" {
}

resource "google_pubsub_topic_iam_binding" "gcs_publisher" {
  topic = google_pubsub_topic.recon_topic.name
  role  = "roles/pubsub.publisher"

  members = [
    "serviceAccount:${data.google_storage_project_service_account.gcs_account.email_address}"
  ]
}

# -----------------------------------------------------------------------------
# 4. The Trigger Configuration
# -----------------------------------------------------------------------------
resource "google_storage_notification" "bucket_notification" {
  bucket         = google_storage_bucket.honeypot_bucket.name
  payload_format = "JSON_API_V1"
  topic          = google_pubsub_topic.recon_topic.id
  event_types    = ["OBJECT_FINALIZE"] # Only trigger when a file is fully written/created

  # We strictly depend on the IAM binding. If we create this notification 
  # before the permission exists, GCP will throw an error.
  depends_on = [google_pubsub_topic_iam_binding.gcs_publisher]
}