# Capstone-Project

## Problem Statement:
Design and implement an end-to-end cloud infrastructure automation and deployment solution using Terraform, Ansible, Docker, and Kubernetes.

## Terraform Task:

### Problem Statement: 
Launch a Ubuntu EC2 instance (t2.micro) to be used as your terraform workstation. From that WS, using Terraform, launch an EC2 
instance (instance type: t2.micro, OS: Ubuntu) to be used as an ansible 
workstation for the ansible task. Please make sure that you create a key (using ssh-keygen) and use it while launching the EC2 so that we can SSH into the 
ansible WS once it is created.

#### Steps:
In your terraform WS, install terraform using following commands
```
sudo apt update
```
```
sudo apt install wget unzip -y
```
```
wget https://releases.hashicorp.com/terraform/1.10.3/terraform_1.10.3_linux_amd64.zip
```
```
unzip terraform_1.10.3_linux_amd64.zip
```
```
sudo mv terraform /usr/local/bin
```
```
rm terraform_1.10.3_linux_amd64.zip
```

Install the aws cli
```
sudo apt-get install python3-pip -y
```
```
sudo pip3 install awscli
```

Use aws configure and give your credentials
```
aws configure
```

Create a directory and inside that directory create your Terraform files to create an instance and ssh into it.
```
mkdir lab
```
```
cd lab
```
```
vi main.tf
```
Copy and post the below configuration
```
provider "aws" {
  profile = "default" # This line is not mandatory.
  region  = "us-east-1"
}
 
resource "aws_instance" "ec2" {
  instance_type = "t2.micro"
  ami = "ami-023c11a32b0207432"                                  
  key_name = "capstone-key"
  depends_on = [ aws_key_pair.capstone-key ]                      #The Key should be created first
  vpc_security_group_ids = [aws_security_group.terraform_sg.id]   #attaching a security group for ssh
  tags = {
    Name = "Ansible Server"}
}

#Generating the Key pair
resource "tls_private_key" "capstone_key_pair" {
  algorithm = "RSA"
  rsa_bits  = 4096
}
#Storing the Public key in AWS
resource "aws_key_pair" "capstone-key" {
  key_name   = "capstone-key"
  public_key = tls_private_key.capstone_key_pair.public_key_openssh  #Passing the Public Key
}
 
#Store the private Key on Local
resource "local_file" "mykey_private" {
  content = tls_private_key.capstone_key_pair.private_key_pem
  filename = "capstone-key"
}
resource "local_file" "mykey_public" {
  content = tls_private_key.capstone_key_pair.public_key_openssh
  filename = "capstone-key.pub"
}


#Creating the security Group and enabling port 22 for ssh
resource "aws_security_group" "terraform_sg" {
  name        = "capstone-allow-ssh"
  description = "security group that allows ssh and all egress traffic"
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "capstone-allow-ssh"
  }
}
```
Initialise the directory
```
terraform init
```
Plan
```
terraform plan
```
Apply
```
terraform apply -auto-approve
```
Once the resources are created, login into the newly created Instance using the below command
```
ssh -i "capstone-key" ubuntu@IP
```



## Ansible Tasks:

### Problem Statement: 

Once you have created a new instance using Terraform (as part of Terraform task), ssh into that instance and install Ansible in it. After that, you have to install httpd webserver in the managed node. You do not have separate managed nodes. So use your ansible workstation itself as the managed node by adding the below line in your host inventory file:
localhost ansible_connection = local

#### Steps:
Install ansible using the following commands
```
sudo apt update
```
```
sudo apt install python3 python3-pip wget -y
```
```
sudo pip3 install boto boto3 ansible
```
```
ansible --version
```



Create a inventory in the location /etc/ansible/hosts and add the below
```
localhost ansible_connection=local
```
Create a directory
```
mkdir ansible-lab && cd ansible-lab
```
```
vi playbook.yaml
```
```
- name: This play will install httpd web servers on all the hosts
  hosts: all
  become: yes
  tasks:
    - name: Task1 will install web-server
      apt:
        name: apache2
        update_cache: yes
        state: latest
    - name: Task2 will start the web-server
      service:
        name: apache2
        state: started
```
Execute the playbook
```
ansible-playbook playbook.yaml
```
Access the webserver on the Ip of the same machine on port 80


## Docker & Kubernetes Task:

### Problem Statement: 
Build a docker image to use the python api and push it to the DockerHub. 
Create a pod and nodeport service with that Docker image.

#### Steps: 
Create a KOPS Cluster. 
```
vi kops.sh
```
```
#!/bin/bash

echo "Let's get started with Kubernetes cluster creation using KOPS!"
echo "Enter your name:"
read username
lower_username=$(echo -e $username | sed 's/ //g' | tr '[:upper:]' '[:lower:]')
date_now=$(date "+%F-%H-%m")
clname=$(echo $lower_username-$date_now.k8s.local)
echo "Your Kubernetes cluster name will be $clname"

TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

az=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)
region=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)

sudo sed -i "/$nrconf{restart}/d" /etc/needrestart/needrestart.conf
echo "\$nrconf{restart} = 'a';" | sudo tee -a /etc/needrestart/needrestart.conf
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

sudo apt update -y
sudo apt install nano curl python3-pip -y
sudo snap install aws-cli --classic

# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x ./kubectl
sudo mv ./kubectl /usr/local/bin/kubectl

# Install kops
curl -LO "https://github.com/kubernetes/kops/releases/download/$(curl -s https://api.github.com/repos/kubernetes/kops/releases/latest | grep tag_name | cut -d '"' -f 4)/kops-linux-amd64"
chmod +x kops-linux-amd64
sudo mv kops-linux-amd64 /usr/local/bin/kops

# Generate SSH key
ssh-keygen -t rsa -N "" -f $HOME/.ssh/id_rsa

# Create S3 bucket for kops state store
aws s3 mb s3://$clname --region $region

# Set KOPS_STATE_STORE environment variable
export KOPS_STATE_STORE=s3://$clname

# Create Kubernetes cluster
kops create cluster --node-count=2 --master-size="t2.medium" --node-size="t2.medium" --master-volume-size=20 --node-volume-size=20 --zones $az --name $clname --ssh-public-key ~/.ssh/id_rsa.pub --yes
kops update cluster $clname --yes

# Export KOPS_STATE_STORE to bashrc
echo "export KOPS_STATE_STORE=s3://$clname" >> /home/ubuntu/.bashrc
source /home/ubuntu/.bashrc

# Export kubectl configuration
kops export kubecfg --admin

# Validate cluster
for (( x=0 ; x < 30 ; x++ )); do
  echo "Validating Cluster"
  if kops validate cluster > status.txt 2>/dev/null && grep -q "is ready" status.txt; then
    echo "Your Cluster is now ready!"
    break
  else
    sleep 20
    echo "x: $x"
  fi
done

# Create Kubernetes Dashboard
cat > kubernetes-dashboard.yaml <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: kubernetes-dashboard

---

apiVersion: v1
kind: ServiceAccount
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard
  namespace: kubernetes-dashboard

---

kind: Service
apiVersion: v1
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard
  namespace: kubernetes-dashboard
spec:
  ports:
    - port: 443
      targetPort: 8443
      nodePort: 32000
  selector:
    k8s-app: kubernetes-dashboard
  type: NodePort

---

apiVersion: v1
kind: Secret
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard-certs
  namespace: kubernetes-dashboard
type: Opaque

---

apiVersion: v1
kind: Secret
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard-csrf
  namespace: kubernetes-dashboard
type: Opaque
data:
  csrf: ""

---

apiVersion: v1
kind: Secret
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard-key-holder
  namespace: kubernetes-dashboard
type: Opaque

---

kind: ConfigMap
apiVersion: v1
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard-settings
  namespace: kubernetes-dashboard

---

kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard
  namespace: kubernetes-dashboard
rules:
  # Allow Dashboard to get, update and delete Dashboard exclusive secrets.
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["kubernetes-dashboard-key-holder", "kubernetes-dashboard-certs", "kubernetes-dashboard-csrf"]
    verbs: ["get", "update", "delete"]
    # Allow Dashboard to get and update 'kubernetes-dashboard-settings' config map.
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["kubernetes-dashboard-settings"]
    verbs: ["get", "update"]
    # Allow Dashboard to get metrics.
  - apiGroups: [""]
    resources: ["services"]
    resourceNames: ["heapster", "dashboard-metrics-scraper"]
    verbs: ["proxy"]
  - apiGroups: [""]
    resources: ["services/proxy"]
    resourceNames: ["heapster", "http:heapster:", "https:heapster:", "dashboard-metrics-scraper", "http:dashboard-metrics-scraper"]
    verbs: ["get"]

---

kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard
rules:
  # Allow Metrics Scraper to get metrics from the Metrics server
  - apiGroups: ["metrics.k8s.io"]
    resources: ["pods", "nodes"]
    verbs: ["get", "list", "watch"]

---

apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard
  namespace: kubernetes-dashboard
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: kubernetes-dashboard
subjects:
  - kind: ServiceAccount
    name: kubernetes-dashboard
    namespace: kubernetes-dashboard

---

apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kubernetes-dashboard
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: kubernetes-dashboard
subjects:
  - kind: ServiceAccount
    name: kubernetes-dashboard
    namespace: kubernetes-dashboard

---

kind: Deployment
apiVersion: apps/v1
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard
  namespace: kubernetes-dashboard
spec:
  replicas: 1
  revisionHistoryLimit: 10
  selector:
    matchLabels:
      k8s-app: kubernetes-dashboard
  template:
    metadata:
      labels:
        k8s-app: kubernetes-dashboard
    spec:
      containers:
        - name: kubernetes-dashboard
          image: kubernetesui/dashboard:v2.4.0
          imagePullPolicy: Always
          ports:
            - containerPort: 8443
              protocol: TCP
          args:
            - --auto-generate-certificates
            - --namespace=kubernetes-dashboard
            # Uncomment the following line to manually specify Kubernetes API server Host
            # If not specified, Dashboard will attempt to auto discover the API server and connect
            # to it. Uncomment only if the default does not work.
            # - --apiserver-host=http://my-address:port
          volumeMounts:
            - name: kubernetes-dashboard-certs
              mountPath: /certs
              # Create on-disk volume to store exec logs
            - mountPath: /tmp
              name: tmp-volume
          livenessProbe:
            httpGet:
              scheme: HTTPS
              path: /
              port: 8443
            initialDelaySeconds: 30
            timeoutSeconds: 30
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsUser: 1001
      securityContext:
        fsGroup: 2001
      serviceAccountName: kubernetes-dashboard
      volumes:
        - name: kubernetes-dashboard-certs
          secret:
            secretName: kubernetes-dashboard-certs
        - name: tmp-volume
          emptyDir: {}
---

kind: ServiceAccount
apiVersion: v1
metadata:
  name: kubernetes-dashboard
  namespace: kubernetes-dashboard

---

kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: kubernetes-dashboard
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: kubernetes-dashboard
  namespace: kubernetes-dashboard
EOF

kubectl apply -f kubernetes-dashboard.yaml

# Retrieve URL of the Kubernetes Dashboard
urls=()
for i in {2..4}; do
  urls+=("https://$(kubectl get nodes -o wide -n kubernetes-dashboard | awk 'NR=='$i'{print $7}')":32000)
done

# Generate token.txt file with URLs and token
{
  echo "                                                   "
  echo "********        HERE ARE THE DETAILS REQUIRED        ********"
  echo "******** You can use any one of the below given URLs ********"
  for url in "${urls[@]}"; do
    echo "URL: $url"
  done
  echo "Creating Token"
  echo "Token is:"
  kubectl -n kube-system describe secret "$(kubectl -n kube-system get secret | grep kops-admin | awk '{print $1}')" | grep token: | awk '{print $2}'
  echo "******************          END          ******************"
  echo "                                                   "
} > token.txt

cat token.txt
```
```
. ./kops.sh
```
  
You can use the worker nodes to write DockerFile and build images. Create the DockerFile, requirements.txt and python api code in the same directory. Use the following commands to build the image and push it to Docker hub
```
mkdir task3 && cd task3
```
```
vi requirements.txt
```
```
Flask==1.0.1
requests==2.8.1
```
```
vi Dockerfile
```
```Dockerfile
FROM ubuntu:18.04
LABEL maintainer="Admin CloudThat"
RUN apt-get update -y && \
    apt-get install -y python-pip python-dev
COPY ./requirements.txt /app/requirements.txt
WORKDIR /app
RUN pip install -r requirements.txt
COPY ./code /app
CMD [ "python", "./app.py" ]
```
Create a director `code`
```
mkdir code && cd code
```
```
vi app.py
```
```
#!/usr/bin/env python3.8
# -*- coding: utf-8 -*-
import os

from flask import Flask, jsonify, request

app = Flask(__name__)

notes = [
    {
        "author": "hightower",
        "title": "Kubernetes up and Running"
    },
    {
        "author": "navathe",
        "title": "Database Fundamentals"
    },
    {
        "author": "ritchie",
        "title": "Let us C"
    }
]

@app.route("/")
def hello():
    return "Welcome to my bookstore!"

@app.route("/v1/books/")
def list_all_books():
    list = []
    for item in notes:
       list.append({'book':item['title']})
    return jsonify(list)

@app.route("/v1/books/<string:author>")
def get_by_author(author):
    for item in notes:
	    if item['author'] == author:
	       data = item
    return jsonify(data)
    if not item:
        return jsonify({'error': 'Author does not exist'}), 404

@app.route("/v1/books/", methods=["POST"])
def add_book():
    author = request.json.get('author')
    book = request.json.get('title')
    if not author or not book:
        return jsonify({'error': 'Please provide Author and Title'}), 400
    else:
        data = request.get_json()
        notes.append(data)
        return jsonify({'message': 'Added book successfully','author':author,'book': book}),200

if __name__ == '__main__':
    app.run(threaded=True, host='0.0.0.0', port=5000)
```
```
cd ..
```
```
docker login -u <username>
```
```
docker build -t <username>/test-flask-app:v1 .
```
```
docker push <username>/test-flask-app:v1 
```

Now deploy the app.

In the jumper node create a pod that uses the above created image. Use the pod.yaml file.
```
vi pod.yaml
```
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: flask-pod
  labels:
    app: flask-app
spec:
  containers:
  - name: flask-app
    image: mandarct/my-flask-demo		##change this iamge name
    ports:
      - containerPort: 5000
```
Use the following command to create the pod and a service for that pod
```
kubectl apply -f pod.yaml
```
```
kubectl expose po flask-pod --type NodePort --port 5000
```
```
kubectl get svc
```
Use the public IP of the worker nodes and nodeport number to access in web page

Example
* http://PublicIP:NodePort_no/v1/books/
* http://PublicIP:NodePort_no/v1/books/navathe
* http://PublicIP:NodePort_no/v1/books/hightower
* http://PublicIP:NodePort_no/v1/books/ritchie
