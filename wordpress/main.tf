# Конфігурація провайдерів
terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.44.1"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.32.0"
    }
    kubectl = {
      source  = "gavinbunney/kubectl"
      version = "~> 1.14.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.5.0"
    }
  }
  required_version = ">= 1.0.0"
}

# Змінні
variable "project_id" {
  type        = string
  description = "The ID of the Google Cloud project"
}

variable "region" {
  type        = string
  description = "The region to deploy resources in"
}

variable "zones" {
  type        = list(string)
  description = "The zones where the resources will be created"
}

variable "cluster_name" {
  type        = string
  description = "The name of the GKE cluster"
}

variable "wordpress_db_password" {
  type        = string
  description = "Password for WordPress database"
  sensitive   = true
}

variable "postgres_db_password" {
  type        = string
  description = "Password for PostgreSQL database"
  sensitive   = true
}

variable "argocd_admin_password" {
  type        = string
  description = "Admin password for ArgoCD"
  sensitive   = true
}

variable "grafana_admin_password" {
  type        = string
  description = "Admin password for Grafana"
  sensitive   = true
}

# Налаштування провайдера Google
provider "google" {
  project = var.project_id
  region  = var.region
}

# Налаштування провайдера Kubernetes
provider "kubernetes" {
  host                   = "https://${module.gke.endpoint}"
  token                  = data.google_client_config.default.access_token
  cluster_ca_certificate = base64decode(module.gke.ca_certificate)
}

provider "helm" {
  kubernetes {
    host                   = "https://${module.gke.endpoint}"
    token                  = data.google_client_config.default.access_token
    cluster_ca_certificate = base64decode(module.gke.ca_certificate)
  }
}

provider "kubectl" {
  host                   = "https://${module.gke.endpoint}"
  token                  = data.google_client_config.default.access_token
  cluster_ca_certificate = base64decode(module.gke.ca_certificate)
  load_config_file       = false
}

data "google_client_config" "default" {}

# Увімкнення необхідних API
resource "google_project_service" "services" {
  for_each = toset([
    "cloudscheduler.googleapis.com",
    "container.googleapis.com",
    "sqladmin.googleapis.com",
    "file.googleapis.com"
  ])
  project = var.project_id
  service = each.key

  disable_on_destroy = false
}

# VPC
resource "google_compute_network" "vpc_network" {
  name                    = "vpc-network"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "subnet" {
  name          = "subnet-${var.region}"
  ip_cidr_range = "10.0.0.0/16"
  region        = var.region
  network       = google_compute_network.vpc_network.id

  secondary_ip_range {
    range_name    = "gke-pods-range"
    ip_cidr_range = "10.4.0.0/16"
  }

  secondary_ip_range {
    range_name    = "gke-services-range"
    ip_cidr_range = "10.5.0.0/20"
  }
}

# Firewall
resource "google_compute_firewall" "allow-internal" {
  name    = "allow-internal"
  network = google_compute_network.vpc_network.name

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }

  source_ranges = ["10.0.0.0/16"]
}

resource "google_compute_firewall" "allow-external" {
  name    = "allow-external"
  network = google_compute_network.vpc_network.name

  allow {
    protocol = "tcp"
    ports    = ["80", "443", "3306", "5432"]
  }

  source_ranges = ["0.0.0.0/0"]
}

# GKE Кластер
module "gke" {
  source                   = "terraform-google-modules/kubernetes-engine/google"
  version                  = "33.0.4"
  project_id               = var.project_id
  name                     = var.cluster_name
  region                   = var.region
  zones                    = var.zones
  network                  = google_compute_network.vpc_network.name
  subnetwork               = google_compute_subnetwork.subnet.name
  ip_range_pods            = "gke-pods-range"
  ip_range_services        = "gke-services-range"
  create_service_account   = false
  remove_default_node_pool = true
  initial_node_count       = 1
  node_pools = [
    {
      name               = "default-node-pool"
      machine_type       = "e2-medium"
      min_count          = 1
      max_count          = 3
      disk_size_gb       = 100
      disk_type          = "pd-standard"
      auto_repair        = true
      auto_upgrade       = true
    },
  ]
}

# Filestore
resource "google_filestore_instance" "nfs" {
  name     = "nfs-instance"
  location = var.zones[0]
  tier     = "BASIC_HDD"

  file_shares {
    name        = "wordpress_data"
    capacity_gb = 1024
  }

  networks {
    network = google_compute_network.vpc_network.name
    modes   = ["MODE_IPV4"]
  }
}

# MySQL
resource "google_sql_database_instance" "mysql_instance" {
  name             = "mysql-instance"
  database_version = "MYSQL_8_0"
  region           = var.region

  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled = true
      authorized_networks {
        name  = "All"
        value = "0.0.0.0/0"
      }
    }
  }
  deletion_protection = false
}

resource "google_sql_database" "wordpress_db" {
  name     = "wordpress"
  instance = google_sql_database_instance.mysql_instance.name
}

resource "google_sql_user" "wordpress_user" {
  name     = "wordpress"
  instance = google_sql_database_instance.mysql_instance.name
  password = var.wordpress_db_password
}

# PostgreSQL
resource "google_sql_database_instance" "postgres_instance" {
  name             = "postgres-instance"
  database_version = "POSTGRES_13"
  region           = var.region

  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled = true
    }
    backup_configuration {
      enabled    = true
      start_time = "03:00"
    }
  }

  deletion_protection = false
}

resource "google_sql_database" "backup_db" {
  name     = "backup"
  instance = google_sql_database_instance.postgres_instance.name
}

resource "google_sql_user" "backup_user" {
  name     = "backupuser"
  instance = google_sql_database_instance.postgres_instance.name
  password = var.postgres_db_password
}

# Backup
resource "google_storage_bucket" "backup_bucket" {
  name     = "${var.project_id}-backups"
  location = var.region
  
  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type = "Delete"
    }
  }
}

# Cloud Scheduler
resource "google_service_account" "scheduler_sa" {
  account_id   = "scheduler-sa"
  display_name = "Cloud Scheduler Service Account"
}

resource "google_project_iam_member" "scheduler_sa_role" {
  project = var.project_id
  role    = "roles/cloudsql.admin"
  member  = "serviceAccount:${google_service_account.scheduler_sa.email}"
}

resource "google_cloud_scheduler_job" "postgres_backup" {
  name             = "postgres-backup-job"
  description      = "Trigger PostgreSQL backup"
  schedule         = "0 1 * * *"
  time_zone        = "UTC"
  attempt_deadline = "320s"

  http_target {
    http_method = "POST"
    uri         = "https://sqladmin.googleapis.com/sql/v1beta4/projects/${var.project_id}/instances/${google_sql_database_instance.postgres_instance.name}/export"
    
    oauth_token {
      service_account_email = google_service_account.scheduler_sa.email
    }

    body = base64encode(jsonencode({
      exportContext = {
        fileType  = "SQL"
        uri       = "gs://${google_storage_bucket.backup_bucket.name}/postgres/${google_sql_database_instance.postgres_instance.name}-${timestamp()}.sql"
        databases = [google_sql_database.backup_db.name]
      }
    }))
  }

  depends_on = [google_project_service.services, google_service_account.scheduler_sa]
}

# Kubernetes ресурси
resource "kubernetes_persistent_volume" "wordpress_pv" {
  metadata {
    name = "wordpress-pv"
  }
  spec {
    capacity = {
      storage = "20Gi"
    }
    access_modes = ["ReadWriteMany"]
    persistent_volume_source {
      nfs {
        path   = "/${google_filestore_instance.nfs.file_shares[0].name}"
        server = google_filestore_instance.nfs.networks[0].ip_addresses[0]
      }
    }
    storage_class_name = "wordpress" 
  }
}

resource "kubernetes_persistent_volume_claim" "wordpress_pvc" {
  metadata {
    name = "wordpress-pvc"
  }
  spec {
    access_modes = ["ReadWriteMany"]
    resources {
      requests = {
        storage = "20Gi"
      }
    }
    volume_name = kubernetes_persistent_volume.wordpress_pv.metadata[0].name
    storage_class_name = "wordpress"
  }
}

resource "kubernetes_deployment" "wordpress" {
  metadata {
    name = "wordpress"
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "wordpress"
      }
    }

    template {
      metadata {
        labels = {
          app = "wordpress"
        }
      }

      spec {
        container {
          image = "wordpress:latest"
          name  = "wordpress"

          env {
            name  = "WORDPRESS_DB_HOST"
            value = google_sql_database_instance.mysql_instance.public_ip_address
          }
          env {
            name  = "WORDPRESS_DB_USER"
            value = google_sql_user.wordpress_user.name
          }
          env {
            name  = "WORDPRESS_DB_PASSWORD"
            value = var.wordpress_db_password
          }
          env {
            name  = "WORDPRESS_DB_NAME"
            value = google_sql_database.wordpress_db.name
          }

          volume_mount {
            name       = "wordpress-persistent-storage"
            mount_path = "/var/www/html"
          }
        }

        volume {
          name = "wordpress-persistent-storage"
          persistent_volume_claim {
            claim_name = kubernetes_persistent_volume_claim.wordpress_pvc.metadata[0].name
          }
        }
      }
    }
  }
}

resource "kubernetes_service" "wordpress" {
  metadata {
    name = "wordpress"
  }

  spec {
    selector = {
      app = "wordpress"
    }
    port {
      port        = 80
      target_port = 80
    }
    type = "LoadBalancer"
  }
}

# phpMyAdmin
resource "kubernetes_deployment" "phpmyadmin" {
  metadata {
    name = "phpmyadmin"
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "phpmyadmin"
      }
    }

    template {
      metadata {
        labels = {
          app = "phpmyadmin"
        }
      }

      spec {
        container {
          image = "phpmyadmin/phpmyadmin:latest"
          name  = "phpmyadmin"

          env {
            name  = "PMA_HOST"
            value = google_sql_database_instance.mysql_instance.public_ip_address
          }
          env {
            name  = "MYSQL_ROOT_PASSWORD"
            value = var.wordpress_db_password
          }
        }
      }
    }
  }
}

resource "kubernetes_service" "phpmyadmin" {
  metadata {
    name = "phpmyadmin"
  }

  spec {
    selector = {
      app = "phpmyadmin"
    }
    port {
      port        = 80
      target_port = 80
    }
    type = "LoadBalancer"
  }
}

# ArgoCD
resource "helm_release" "argocd" {
  name             = "argocd"
  repository       = "https://argoproj.github.io/argo-helm"
  chart            = "argo-cd"
  version          = "5.29.1"
  namespace        = "argocd"
  create_namespace = true

  values = [
    <<-EOF
    server:
      service:
        type: LoadBalancer
    EOF
  ]

  set {
    name  = "configs.secret.argocdServerAdminPassword"
    value = bcrypt(var.argocd_admin_password)
  }
}

resource "kubectl_manifest" "argocd_application" {
  yaml_body = <<YAML
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: wordpress-app
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/Alazzze/argoCD
    targetRevision: main
    path: wordpress
  destination:
    server: https://kubernetes.default.svc
    namespace: default
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
YAML

  depends_on = [helm_release.argocd]
}

# Grafana
resource "helm_release" "grafana" {
  name             = "grafana"
  repository       = "https://grafana.github.io/helm-charts"
  chart            = "grafana"
  version          = "6.50.7"
  namespace        = "monitoring"
  create_namespace = true

  set_sensitive {
    name  = "adminPassword"
    value = var.grafana_admin_password
  }

  set {
    name  = "service.type"
    value = "LoadBalancer"
  }

  set {
    name  = "persistence.enabled"
    value = "true"
  }

  set {
    name  = "persistence.size"
    value = "10Gi"
  }
}

# Outputs
output "kubernetes_cluster_name" {
  value       = module.gke.name
  description = "GKE Cluster Name"
}

output "kubernetes_cluster_host" {
  value       = module.gke.endpoint
  description = "GKE Cluster Host"
}

output "wordpress_ip" {
  value       = kubernetes_service.wordpress.status[0].load_balancer[0].ingress[0].ip
  description = "WordPress LoadBalancer IP"
}

output "phpmyadmin_ip" {
  value       = kubernetes_service.phpmyadmin.status[0].load_balancer[0].ingress[0].ip
  description = "phpMyAdmin LoadBalancer IP"
}

output "argocd_server_url" {
  value       = "https://${kubernetes_service.argocd.status[0].load_balancer[0].ingress[0].ip}"
  description = "URL для доступу до сервера ArgoCD"
}

output "grafana_ip" {
  value       = kubernetes_service.grafana.status[0].load_balancer[0].ingress[0].ip
  description = "IP-адреса для доступу до Grafana"
}

output "mysql_instance_connection_name" {
  value       = google_sql_database_instance.mysql_instance.connection_name
  description = "MySQL instance connection name"
}

output "postgres_instance_connection_name" {
  value       = google_sql_database_instance.postgres_instance.connection_name
  description = "PostgreSQL instance connection name"
}
