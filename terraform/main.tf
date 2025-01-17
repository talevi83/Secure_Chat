terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  profile = "default"  # or whatever profile name you're using
}

# VPC
resource "aws_vpc" "chat_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "chat-server-vpc"
  }
}

# Public Subnet
resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.chat_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}a"

  tags = {
    Name = "chat-server-public-subnet"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "chat_igw" {
  vpc_id = aws_vpc.chat_vpc.id

  tags = {
    Name = "chat-server-igw"
  }
}

# Route Table
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.chat_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.chat_igw.id
  }

  tags = {
    Name = "chat-server-public-rt"
  }
}

# Route Table Association
resource "aws_route_table_association" "public_rt_assoc" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

# Security Group
resource "aws_security_group" "chat_server_sg" {
  name        = "chat-server-sg"
  description = "Security group for chat server"
  vpc_id      = aws_vpc.chat_vpc.id

  ingress {
    from_port   = var.chat_server_port
    to_port     = var.chat_server_port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Chat server port"
  }

  ingress {
    from_port   = var.monitoring_port
    to_port     = var.monitoring_port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Monitoring interface port"
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "chat-server-sg"
  }
}

# EC2 Instance
resource "aws_instance" "chat_server" {
  ami           = var.ami_id
  instance_type = var.instance_type

  subnet_id                   = aws_subnet.public_subnet.id
  vpc_security_group_ids      = [aws_security_group.chat_server_sg.id]
  associate_public_ip_address = true
  key_name                   = "chat_server_key" # var.key_pair_name

  user_data = <<-EOF
              #!/bin/bash
              # Enable detailed logging
              exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1

              echo "Starting user data script execution..."

              # Update and install required packages
              echo "Updating system packages..."
              apt-get update
              apt-get install -y docker.io git

              # Start and enable docker
              echo "Starting Docker service..."
              systemctl start docker
              systemctl enable docker

              # Add ubuntu user to docker group
              echo "Adding ubuntu user to docker group..."
              usermod -aG docker ubuntu

              # Install Docker Compose
              echo "Installing Docker Compose..."
              curl -L "https://github.com/docker/compose/releases/download/v2.23.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
              chmod +x /usr/local/bin/docker-compose

              # Create app directory and set permissions
              echo "Setting up application directory..."
              mkdir -p /app
              cd /app

              # Clone repository
              echo "Cloning repository..."
              if git clone https://github.com/talevi83/Secure_Chat.git .; then
                echo "Repository cloned successfully"
              else
                echo "Failed to clone repository"
                exit 1
              fi

              # Set correct permissions
              echo "Setting permissions..."
              chown -R ubuntu:ubuntu /app

              # Check if docker-compose.yml exists
              echo "Checking docker-compose.yml..."

              if [! -f "/app/docker-compose.yml" ]; then
                echo "docker-compose.yml not found!"
                ls -la /app
                exit 1
              fi

              sudo -i
              # Start the containers
              if [ ! -f "/app/docker-compose.yml" ]; then
                echo "docker-compose.yml not found!"
                ls -la /app
                exit 1
              fi

              # Start the containers
              echo "Starting containers with docker-compose..."
              sudo docker-compose up --build -d

              echo "Script completed successfully"
              EOF
  tags = {
    Name = "chat-server"
  }
}

# Output the public IP and DNS
output "public_ip" {
  value = aws_instance.chat_server.public_ip
}

output "public_dns" {
  value = aws_instance.chat_server.public_dns
}

output "aws_region" {
  value = data.aws_region.current.name
}

data "aws_region" "current" {}

