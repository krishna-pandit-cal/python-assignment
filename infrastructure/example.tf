# example.tf
# This file contains intentional IaC misconfigurations for testing iac_linter.py

provider "aws" {
  region = "us-east-1"
}

# Open security group (0.0.0.0/0) on sensitive ports (SSH)
resource "aws_security_group" "open_sg" {
  name        = "open_sg"
  description = "Security group with open SSH and HTTP access"

  ingress {
    description = "SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP access"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "open_sg"
  }
}

# Public S3 bucket
resource "aws_s3_bucket" "public_bucket" {
  bucket = "test-public-bucket"
  acl    = "public-read"
  # intentionally missing tags
}

# IAM policy with wildcard permissions
resource "aws_iam_policy" "wildcard_policy" {
  name        = "wildcard_policy"
  description = "Policy that allows all actions on all resources"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# RDS instance with hardcoded password
resource "aws_db_instance" "bad_db" {
  identifier              = "mydb"
  engine                  = "mysql"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  username                = "admin"
  password                = "SuperSecret123" # <- hardcoded secret
  publicly_accessible     = true
  skip_final_snapshot     = true
  db_subnet_group_name    = "default"
  vpc_security_group_ids  = [aws_security_group.open_sg.id]
  # missing tags
}
