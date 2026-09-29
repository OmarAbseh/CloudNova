# An internet-exposed EC2 instance that can assume an admin role which can
# read a sensitive S3 bucket — a full attack chain, not just isolated findings.

resource "aws_security_group" "web" {
  name = "web-sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "web" {
  ami                    = "ami-123"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.web.id]
  iam_instance_profile   = aws_iam_instance_profile.app.name
}

resource "aws_iam_instance_profile" "app" {
  name = "app-profile"
  role = aws_iam_role.app.name
}

resource "aws_iam_role" "app" {
  name = "app-role"
}

resource "aws_iam_role_policy" "admin" {
  name   = "admin"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}

resource "aws_s3_bucket" "sensitive" {
  bucket = "customer-pii"
}
