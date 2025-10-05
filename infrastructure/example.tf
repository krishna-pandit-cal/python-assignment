provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "open_sg" {
  name        = "open-sg"
  description = "Security group with open ingress"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Environment = "dev"
  }
}

resource "aws_s3_bucket" "test_bucket" {
  bucket = "example-bucket"
  acl    = "public-read"

  tags = {
    Owner = "krishna"
  }
}
