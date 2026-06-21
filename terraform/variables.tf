variable "project_id" {
  type        = string
  description = "The GCP Project ID"
  default     = "web-vulnarebility-scanner"
}

variable "region" {
  type        = string
  description = "The target deployment GCP region"
  default     = "us-central1"
}

variable "env" {
  type        = string
  description = "The deployment environment"
  default     = "dev"
}

variable "firebase_config_secret" {
  type        = string
  description = "Firebase Admin configuration JSON string"
  default     = "{}"
}
