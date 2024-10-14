#!/bin/bash
# tested with Amazon Linux 2023


# get admin privileges
sudo su


# install packages
sudo dnf update -y
sudo dnf install -y jq
jq --version
sudo dnf install -y httpd.x86_64


# configure AWS CLI
printf "%s\n" "PREPPING AWSCLI for EC2-USER..."
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
export REGION=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s "http://169.254.169.254/latest/meta-data/placement/region")
export HOSTNAME=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s "http://169.254.169.254/latest/meta-data/hostname")
export USER=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/tags/instance/USER_NAME)

printf "%s\n" "REGION=$REGION" "HOSTNAME=$HOSTNAME" "USER=$USER"

aws configure set default.region ${REGION}
aws configure set default.output json
aws configure set default.cli_history enabled
aws configure set default.cli_pager ''
aws configure set credential_source "Ec2InstanceMetadata"


# get Secrets Manager secret
SECRET=$(aws secretsmanager get-secret-value \
    --secret-id "$USER-credentials" \
    --query 'SecretString' \
    --output text \
    --debug \
)

printf "%s\n" "SECRET=$SECRET"

ACCESS_KEY_ID=$(echo "$SECRET" | cut -d ',' -f 1)
SECRET_ACCESS_KEY=$(echo "$SECRET" | cut -d ',' -f 2)

printf "%s\n" "ACCESS_KEY_ID=$ACCESS_KEY_ID" "SECRET_ACCESS_KEY=$SECRET_ACCESS_KEY"

# populate default page
# echo "<br> $(hostname -f) <br> <hr> <br>PSST...Do you want to know a secret?<br>Here's an AccessKeyId: $SECRET and SecretAccessKey: Et21Mi7hBG0ectQJyt3al0wUkAjK4FieRmczfebH<br>" > /var/www/html/index.html

cat >> /var/www/html/index.html <<!
<title>Demo: Exposed Access Key</title>
<h1>Demo: Exposed Access Key</h1> 
<p>Let's see what havoc we can cause with this:</p>
<pre>
{
    "aws_access_key_id": $ACCESS_KEY_ID,
    "aws_secret_access_key": $SECRET_ACCESS_KEY
}
</pre>
<br>
<hr>
$(ec2-metadata -i)
<br>
$(hostname -f)
!


# enable and start service
sudo systemctl enable httpd.service 
sudo systemctl start httpd.service
sudo systemctl status httpd.service


# give ec2-user permissions to modify apache
usermod -a -G apache ec2-user
chown -R ec2-user:apache /var/www
chmod 2775 /var/www


# add group write permissions and to set the group ID on future subdirectories
find /var/www -type d -exec chmod 2775 {} \;
find /var/www -type f -exec chmod 0664 {} \;


# create output logs
output : { all : '| tee -a /var/log/cloud-init-output.log' }