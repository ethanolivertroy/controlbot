terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-gov-west-1"
}

# Intentionally weak config for scanner + NIST mapping demo
resource "aws_s3_bucket" "data_lake" {
  bucket = "demo-nist-reviewer-data-lake"
}

resource "aws_security_group" "app" {
  name        = "demo-app-sg"
  description = "Demo app security group"
  vpc_id      = "vpc-placeholder"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "app_db" {
  identifier           = "demo-app-db"
  engine               = "postgres"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "changeme-not-for-production"
  skip_final_snapshot  = true
  publicly_accessible  = true
  storage_encrypted    = false
}

# Demo PR change — adds another insecure SG rule for Compliance Bot inline review
resource "aws_security_group_rule" "demo_https_open" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.app.id
}

