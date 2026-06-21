provider "google" {
  project = var.project_id
  region  = var.region
}

# Local variables for consistent labeling
locals {
  common_labels = {
    env        = var.env
    project    = var.project_id
    managed_by = "terraform"
  }
}

# --- 1. VPC Network & Private Connectivity ---
resource "google_compute_network" "vpc" {
  name                    = "scanner-vpc-${var.env}"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "subnet" {
  name          = "scanner-subnet-${var.env}"
  ip_cidr_range = "10.0.0.0/24"
  network       = google_compute_network.vpc.id
  region        = var.region
}

# Private IP allocation for Cloud SQL private services access
resource "google_compute_global_address" "private_ip_alloc" {
  name          = "private-ip-alloc-${var.env}"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.vpc.id
}

# VPC Connection to Service Networking for Cloud SQL
resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = google_compute_network.vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_alloc.name]
}

# Serverless VPC Access connector for Cloud Run
resource "google_vpc_access_connector" "connector" {
  name          = "vpc-conn-${var.env}"
  region        = var.region
  ip_cidr_range = "10.8.0.0/28"
  network       = google_compute_network.vpc.id
  min_instances = 2
  max_instances = 10
}

# --- 2. Cloud SQL PostgreSQL Instance ---
resource "google_sql_database_instance" "db_instance" {
  name             = "scanner-db-${var.env}"
  database_version = "POSTGRES_15"
  region           = var.region
  
  depends_on = [google_service_networking_connection.private_vpc_connection]

  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.vpc.id
    }
    user_labels = local.common_labels
  }
  
  deletion_protection = false
}

resource "google_sql_database" "database" {
  name     = "scanner"
  instance = google_sql_database_instance.db_instance.name
}

resource "google_sql_user" "db_user" {
  name     = "postgres"
  instance = google_sql_database_instance.db_instance.name
  password = "securepassword123"
}

# --- 3. Cloud Memorystore Redis ---
resource "google_redis_instance" "redis_instance" {
  name                    = "scanner-redis-${var.env}"
  tier                    = "BASIC"
  memory_size_gb          = 1
  region                  = var.region
  authorized_network      = google_compute_network.vpc.id
  connect_mode            = "PRIVATE_SERVICE_ACCESS"
  
  auth_enabled            = true
  transit_encryption_mode = "SERVER_AUTHENTICATION"

  labels = local.common_labels

  depends_on = [google_service_networking_connection.private_vpc_connection]
}

# --- 4. Secret Manager Configuration ---
resource "google_secret_manager_secret" "db_url" {
  secret_id = "database-url-${var.env}"
  replication {
    auto {}
  }
  labels = local.common_labels
}

resource "google_secret_manager_secret_version" "db_url_v1" {
  secret      = google_secret_manager_secret.db_url.id
  secret_data = "postgresql://${google_sql_user.db_user.name}:${google_sql_user.db_user.password}@${google_sql_database_instance.db_instance.private_ip_address}:5432/${google_sql_database.database.name}"
}

resource "google_secret_manager_secret" "redis_url" {
  secret_id = "redis-url-${var.env}"
  replication {
    auto {}
  }
  labels = local.common_labels
}

resource "google_secret_manager_secret_version" "redis_url_v1" {
  secret      = google_secret_manager_secret.redis_url.id
  secret_data = "redis://:${google_redis_instance.redis_instance.auth_string}@${google_redis_instance.redis_instance.host}:${google_redis_instance.redis_instance.port}/0"
}

resource "google_secret_manager_secret" "firebase_config" {
  secret_id = "firebase-config-${var.env}"
  replication {
    auto {}
  }
  labels = local.common_labels
}

resource "google_secret_manager_secret_version" "firebase_config_v1" {
  secret      = google_secret_manager_secret.firebase_config.id
  secret_data = var.firebase_config_secret
}

# --- 5. Cloud Run API Service ---
resource "google_cloud_run_v2_service" "api_service" {
  name     = "scanner-api-${var.env}"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"

  template {
    containers {
      image = "gcr.io/${var.project_id}/backend:latest"
      
      ports {
        container_port = 8000
      }

      env {
        name = "DATABASE_URL"
        value_source {
          secret_key_ref {
            secret = google_secret_manager_secret.db_url.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "REDIS_URL"
        value_source {
          secret_key_ref {
            secret = google_secret_manager_secret.redis_url.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "ENVIRONMENT"
        value = "prod"
      }

      startup_probe {
        http_get {
          path = "/health"
          port = 8000
        }
        initial_delay_seconds = 10
        period_seconds        = 5
        failure_threshold     = 3
      }
    }

    vpc_access {
      connector = google_vpc_access_connector.connector.id
      egress    = "ALL_TRAFFIC"
    }

    labels = local.common_labels
  }

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }
}

# --- 6. Cloud Run Worker Service ---
resource "google_cloud_run_v2_service" "worker_service" {
  name     = "scanner-worker-${var.env}"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_NONE"  # Completely private service, inaccessible from web

  template {
    containers {
      image = "gcr.io/${var.project_id}/backend:latest"
      command = ["celery", "-A", "backend.tasks.celery_app", "worker", "--loglevel=info"]
      
      env {
        name = "DATABASE_URL"
        value_source {
          secret_key_ref {
            secret = google_secret_manager_secret.db_url.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "REDIS_URL"
        value_source {
          secret_key_ref {
            secret = google_secret_manager_secret.redis_url.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "ENVIRONMENT"
        value = "prod"
      }
    }

    vpc_access {
      connector = google_vpc_access_connector.connector.id
      egress    = "ALL_TRAFFIC"
    }

    labels = local.common_labels
  }
}

# --- 7. Cloud Run Alembic Migration Job ---
resource "google_cloud_run_v2_job" "migration_job" {
  name     = "scanner-migration-${var.env}"
  location = var.region

  template {
    template {
      containers {
        image = "gcr.io/${var.project_id}/backend:latest"
        command = ["alembic", "upgrade", "head"]

        env {
          name = "DATABASE_URL"
          value_source {
            secret_key_ref {
              secret = google_secret_manager_secret.db_url.secret_id
              version = "latest"
            }
          }
        }
      }
      vpc_access {
        connector = google_vpc_access_connector.connector.id
        egress    = "ALL_TRAFFIC"
      }
      labels = local.common_labels
    }
  }
}

# --- 8. Cloud Armor WAF Policy ---
resource "google_compute_security_policy" "waf_policy" {
  name        = "scanner-waf-policy-${var.env}"
  description = "WAF policy with preconfigured SQLi and XSS protection rules"

  # Default rule (allow all)
  rule {
    action   = "allow"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "default rule"
  }

  # SQLi preconfigured protection rule
  rule {
    action   = "deny(403)"
    priority = "1000"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('sqli-v33-stable')"
      }
    }
    description = "Deny SQLi attempts"
  }

  # XSS preconfigured protection rule
  rule {
    action   = "deny(403)"
    priority = "1010"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('xss-v33-stable')"
      }
    }
    description = "Deny XSS attempts"
  }
}

# --- 9. HTTPS Load Balancer setup ---
# Serverless NEG for backend routing to Cloud Run API
resource "google_compute_region_network_endpoint_group" "serverless_neg" {
  name                  = "serverless-neg-${var.env}"
  network_endpoint_type = "SERVERLESS"
  region                = var.region
  cloud_run {
    service = google_cloud_run_v2_service.api_service.name
  }
}

# Backend Service linking WAF policy
resource "google_compute_backend_service" "backend_service" {
  name            = "scanner-lb-backend-${var.env}"
  protocol        = "HTTP"
  port_name       = "http"
  timeout_sec     = 30
  security_policy = google_compute_security_policy.waf_policy.id

  backend {
    group = google_compute_region_network_endpoint_group.serverless_neg.id
  }
}

# URL Map (Routing rules)
resource "google_compute_url_map" "url_map" {
  name            = "scanner-url-map-${var.env}"
  default_service = google_compute_backend_service.backend_service.id
}

# Target HTTP Proxy (will translate to HTTPS proxy in prod with SSL cert)
resource "google_compute_target_http_proxy" "http_proxy" {
  name    = "scanner-http-proxy-${var.env}"
  url_map = google_compute_url_map.url_map.id
}

# Global Forwarding Rule (Entry IP address)
resource "google_compute_global_forwarding_rule" "forwarding_rule" {
  name       = "scanner-forwarding-rule-${var.env}"
  target     = google_compute_target_http_proxy.http_proxy.id
  port_range = "80"
}
