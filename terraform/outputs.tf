output "lb_ip" {
  value       = google_compute_global_forwarding_rule.forwarding_rule.ip_address
  description = "The public IP address of the HTTPS load balancer routing traffic to the API"
}

output "database_private_ip" {
  value       = google_sql_database_instance.db_instance.private_ip_address
  description = "The private IP address of the Cloud SQL instance"
}

output "redis_host" {
  value       = google_redis_instance.redis_instance.host
  description = "The host connection string for Memorystore Redis"
}

output "redis_port" {
  value       = google_redis_instance.redis_instance.port
  description = "The port connection value for Memorystore Redis"
}

output "vpc_connector_id" {
  value       = google_vpc_access_connector.connector.id
  description = "The resource ID of the Serverless VPC connector"
}
