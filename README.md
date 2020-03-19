<!--
Copyright (c) Dell Inc., or its subsidiaries. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
-->
# Keycloak Security Plugin for Pravega 
[![Build Status](https://travis-ci.com/pravega/pravega-keycloak.svg?branch=master)](https://travis-ci.com/pravega/pravega-keycloak/builds) [![codecov](https://codecov.io/gh/pravega/pravega-keycloak/branch/master/graph/badge.svg)](https://codecov.io/gh/pravega/pravega-keycloak) [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0) [![Version](https://img.shields.io/github/v/release/pravega/pravega-keycloak.svg)](https://github.com/pravega/pravega-keycloak/releases)

## Introduction
This repository contains the source code for the `pravega-keycloak-client` library, which extends Pravega
to use Keycloak Authorization Services to protect Pravega streams.

## Application Configuration
Follow this procedure to connect to a Pravega cluster that is protected by Keycloak.

### 1. Update application dependencies
Update your dependencies to link to the `pravega-keycloak-client` library, which is hosted in the `jcenter` repository. 

For example, in Gradle:
```
repositories {
    jcenter()
    mavenCentral()
}
dependencies {
    implementation "io.pravega:pravega-client:0.7.0"
    implementation "io.pravega:pravega-keycloak-client:0.7.0"
}
```

### 2. Obtain a Keycloak Client Configuration
Your application authenticates to Pravega using credentials found in a Keycloak client configuration file,
which is typically named `keycloak.json`.  Use the Keycloak UI, or consult with product documentation, on how to provision a Keycloak client.

Specific requirements:
1. Access Type: `Confidential`
2. Service Accounts Enabled: `Yes`

A Keycloak client which has a service account is able to be the subject of authorization policies.  See product
documentation on how to grant access to your client to specific Pravega scope(s). 

### 3. Set environment variables
The Pravega client library expects a few environment variables to be set to use the Keycloak extension.

|NAME|VALUE|
|----|-----|
|`pravega_client_auth_method`|`Bearer`|
|`pravega_client_auth_loadDynamic`|`true`|
|`KEYCLOAK_SERVICE_ACCOUNT_FILE`|_Path to Keycloak OIDC JSON client configuration file (`keycloak.json`)._|

## Contributing
Become one of the contributors! We thrive to build a welcoming and open community for anyone who wants to use the system or 
contribute to it. [Here](https://github.com/pravega/pravega/blob/master/documentation/src/docs/contributing.md) we describe how to contribute to Pravega!

## About
Pravega is 100% open source and community-driven. All components are available under [Apache 2 License](https://www.apache.org/licenses/LICENSE-2.0.html) on GitHub.
