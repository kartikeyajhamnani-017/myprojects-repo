variable "project_id" {
  description = "Your Google Cloud Project ID"
  type        = string
}

variable "region" {
  description = "The region for resources (e.g., us-central1)"
  type        = string
  default     = "us-central1"
}

variable "environment" {
  description = "Environment tag (dev/prod)"
  type        = string
  default     = "dev"
}