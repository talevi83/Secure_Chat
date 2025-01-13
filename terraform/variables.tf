variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "ami_id" {
  description = "AMI ID for Ubuntu 22.04 LTS"
  type        = string
  default     = "ami-03f65b8614a860c29"  # Ubuntu 22.04 LTS in us-west-2
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t2.micro"
}

variable "key_pair_name" {
  description = "Name of the AWS key pair to use for SSH access"
  type        = string
  default     = "chat_server_key"  # Updated name
}

variable "chat_server_port" {
  description = "Port for the chat server"
  type        = number
  default     = 8888
}

variable "monitoring_port" {
  description = "Port for the monitoring interface"
  type        = number
  default     = 8080
}