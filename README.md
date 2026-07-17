<p align="center">
  <img src="images/project/logo.svg" height="170" align="middle" alt="TIP OpenWiFi Logo" />
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  <img src="images/project/mango-logo.png" height="90" align="middle" alt="Mango Cloud Logo" />
</p>

# OpenWiFi Security (OWSEC)

## Overview
The OpenWiFi Security (OWSEC) is a core service within the Telecom Infra Project (TIP) OpenWiFi CloudSDK (OWSDK) ecosystem.

OWSEC is the Authentication, Authorization, and Resource Policy Access service for the CloudSDK. Like all other OWSDK microservices, it is defined using an OpenAPI definition and communicates with management UIs and other services through a secure REST API. To use OWSEC, you can either [build it from source](#building) or deploy the containerized version using [Docker](#docker).

## Role in Mango Cloud
This service is part of [Mango Cloud](https://www.mangowifi.cloud/), Router Architects’ open-source platform for managed Wi-Fi and connectivity operations.

Within Mango Cloud, **OWSEC** serves as the central **Security, Authentication, and Access Control Service** (backend node `owsec`).

Key integrations include:
* **Centralized Auth & Tokens**: Acts as the gatekeeper, issuing OAuth2 tokens for dashboard operators, subscribers, and external APIs.
* **Service Discovery**: Manages and exposes system endpoints (via `/systemEndpoints`) so other microservices and UI components can discover and communicate with each other.
* **Role-Based Access Control**: Manages users, roles, resource-access policies and password requirements used by Mango Cloud services to enforce authorization and tenant isolation.

### Resources
* [Mango Cloud Website](https://www.mangowifi.cloud/)
* [Mango Cloud Deployment Guide](https://github.com/routerarchitects/mango-cloud-deployment)
* [Router Architects GitHub Organization](https://github.com/routerarchitects)

### Security Guides
* [Mango Cloud Security](https://www.mangowifi.cloud/security)


## Building
To build the microservice from source, please follow the instructions in [BUILDING.md](./BUILDING.md).

## Docker
To use the containerized CloudSDK deployment, please refer to the deployment guide in the [mango-cloud-deployment](https://github.com/routerarchitects/mango-cloud-deployment) repository.

## OpenAPI
The OWSEC REST API is defined in the OpenAPI specification [openapi/owsec.yaml](https://raw.githubusercontent.com/routerarchitects/ra-wlan-cloud-ucentralsec/main/openapi/owsec.yaml). You can use this OpenAPI definition to inspect endpoints, generate client SDKs, or build static documentation.

## Usage
Like all other OWSDK services, OWSEC is defined through an OpenAPI. You can use this API to build your own applications or integration modules into your own systems. If all you need is to access the OWGW (the service that manages the Access Points), you will need to:
1. Get a token via `/oauth2`.
2. Find the endpoints on the system via `/systemEndpoints`.
3. Choose a microservice to manage (pick an endpoint that matches what you are trying to do by looking at its `type`. For the Cloud SDK Controller, `type = owgw`).
4. Make your calls (use the `PublicEndPoint` of the corresponding entry, adding `/api/v1` as the root of the call).

The CLI for the [OWGW](https://github.com/routerarchitects/ra-wlan-cloud-ucentralgw/blob/main/test_scripts/curl/cli) has a very good example of this. Look for the `setgateway` function.

#### Expected directory layout
From the directory where your cloned source is, you will need to create the `certs`, `logs`, and `uploads` directories.
```bash
mkdir certs
mkdir certs/cas
mkdir logs
mkdir uploads
```
You should now have the following layout:
```text
--+-- certs
  |   +--- cas
  +-- cmake
  +-- cmake-build
  +-- logs
  +-- src
  +-- test_scripts
  +-- openapi
  +-- uploads
  +-- owsec.properties
```

### Certificates
The OWSEC uses a certificate to secure the REST API (Northbound API).

#### The `certs` directory
For all deployments, you will need the following `certs` directory, populated with the proper files.
```text
certs ---+--- restapi-ca.pem
          +--- restapi-cert.pem
          +--- restapi-key.pem
```

## Firewall Considerations
Depending on your deployment, ensure that firewalls allow traffic on the following ports:

| Port  | Service Type / Description | Configurable |
|:------|:-------------------------------------------|:------------:|
| **16001** | Public REST API Access for authentication and management UIs | yes |
| **17001** | Internal REST API Access for intra-microservice communication | yes |
| **16101** | Application Load Balancer (ALB) health check endpoint | yes |

### Environment variables
The following environment variables should be set from the root directory of the service. They tell the OWSEC process where to find the configuration and the root directory.
```bash
export OWSEC_ROOT=`pwd`
export OWSEC_CONFIG=`pwd`
```
You can run the shell script `set_env.sh` from the microservice root.

### OWSEC Service Configuration
The configuration is kept in a file called `owsec.properties`. To understand the configuration details, please see [CONFIGURATION.md](https://github.com/routerarchitects/ra-wlan-cloud-ucentralsec/blob/main/CONFIGURATION.md).

### Default username and password
The default username and password are set in the `owsec.properties` file. The following entries manage the username and password:
```properties
authentication.default.username = tip@ucentral.com
authentication.default.password = XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```
The password is a long sequence of hexadecimal digits. It is the result of hashing the `username` and the `password`. In order to create the password, please follow these simple instructions:
```bash
echo -n "<password><username>" | shasum -a 256
```
Here is a complete example for username `root@system.com` and the password `weLoveWifi`:
```bash
echo -n "weLoveWifiroot@system.com" | shasum -a 256
b5bfed31e2a272e52973a57b95042ab842db3999475f3d79f1ce0f45f465e34c  -
```
Then you need to modify your properties file like this:
```properties
authentication.default.username = root@system.com
authentication.default.password = b5bfed31e2a272e52973a57b95042ab842db3999475f3d79f1ce0f45f465e34c
```
Remember, when you log in, use `root@system.com` with the password `weLoveWifi`, not this hashed digit sequence.

### Changing default password
On the first startup of the service, a new user will be created with the default credentials from properties `authentication.default.username` and `authentication.default.password`, but **you will have to change the password** before making any real requests.
You can do this using `owgw-ui` on first login or using the following script:

```bash
export OWSEC=openwifi.wlan.local:16001 # endpoint to your owsec RESTAPI endpoint
#export FLAGS="-k" # uncomment and add curl flags that you would like to pass for the request (for example '-k' may be used to pass errors with self-signed certificates)
export OWSEC_DEFAULT_USERNAME=root@system.com # default username that you've set in property 'authentication.default.username'
export OWSEC_DEFAULT_PASSWORD=weLoveWifi # default password __in cleartext__ from property 'authentication.default.password'
export OWSEC_NEW_PASSWORD=NewPass123% # new password that must be set for the user (must comply with 'authentication.validation.expression')
test_scripts/curl/cli testlogin $OWSEC_DEFAULT_USERNAME $OWSEC_DEFAULT_PASSWORD $OWSEC_NEW_PASSWORD
```

The CLI is also included in the Docker image if you want to run it this way:

```bash
export OWSEC=openwifi.wlan.local:16001
#export FLAGS="-k"
export OWSEC_DEFAULT_USERNAME=root@system.com
export OWSEC_DEFAULT_PASSWORD=weLoveWifi
export OWSEC_NEW_PASSWORD=NewPass123%
docker run --rm -ti \
  --network=host \
  --env OWSEC \
  --env FLAGS \
  --env OWSEC_DEFAULT_USERNAME \
  --env OWSEC_DEFAULT_PASSWORD \
  --env OWSEC_NEW_PASSWORD \
  tip-tip-wlan-cloud-ucentral.jfrog.io/owsec:main \
  /cli testlogin $OWSEC_DEFAULT_USERNAME $OWSEC_DEFAULT_PASSWORD $OWSEC_NEW_PASSWORD
```

It is very important that you do not use spaces in your `OrgName`.

## Kafka topics
To read more about Kafka integration across microservices, follow the [wlan-cloud-ucentralgw Kafka Documentation](https://github.com/routerarchitects/ra-wlan-cloud-ucentralgw/blob/main/KAFKA.md).

## Contributions
We need more contributors. Should you wish to contribute, please follow the [contributions](https://github.com/routerarchitects/ra-wlan-cloud-ucentralgw/blob/main/CONTRIBUTING.md) document.

## Pull Requests
Please create a branch with the Jira addressing the issue you are fixing or the feature you are implementing. Create a pull-request from the branch into main.

## Additional OWSDK Microservices
Here is a list of additional OWSDK microservices:
| Name | Description | Link | OpenAPI |
| :--- | :--- | :---: | :---: |
| OWSEC | Security Service | [here](https://github.com/routerarchitects/ra-wlan-cloud-ucentralsec) | [here](https://github.com/routerarchitects/ra-wlan-cloud-ucentralsec/blob/main/openapi/owsec.yaml) |
| OWGW | Controller Service | [here](https://github.com/routerarchitects/ra-wlan-cloud-ucentralgw) | [here](https://github.com/routerarchitects/ra-wlan-cloud-ucentralgw/blob/main/openapi/owgw.yaml) |
| OWFMS | Firmware Management Service | [here](https://github.com/routerarchitects/ra-wlan-cloud-ucentralfms) | [here](https://github.com/routerarchitects/ra-wlan-cloud-ucentralfms/blob/main/openapi/owfms.yaml) |
| OWPROV | Provisioning Service | [here](https://github.com/routerarchitects/ra-wlan-cloud-owprov) | [here](https://github.com/routerarchitects/ra-wlan-cloud-owprov/blob/main/openapi/owprov.yaml) |
| OWANALYTICS | Analytics Service | [here](https://github.com/routerarchitects/ra-wlan-cloud-analytics) | [here](https://github.com/routerarchitects/ra-wlan-cloud-analytics/blob/main/openapi/owanalytics.yaml) |
| OWSUB | Subscriber Service | [here](https://github.com/routerarchitects/ra-wlan-cloud-userportal) | [here](https://github.com/routerarchitects/ra-wlan-cloud-userportal/blob/main/openapi/userportal.yaml) |
