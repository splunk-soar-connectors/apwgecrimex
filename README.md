# APWG eCrime Exchange

Publisher: Splunk Community \
Connector Version: 1.0.1 \
Product Vendor: APWG \
Product Name: eCrimeX \
Minimum Product Version: 5.4.0

APWG eCrime Exchange connector

### Configuration variables

This table lists the configuration variables required to operate APWG eCrime Exchange. These variables are specified when configuring a eCrimeX asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**Authorization Key** | required | password | API Key for eCrimeX |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration \
[url reputation](#action-url-reputation) - Queries URL info

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied configuration

Type: **test** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'url reputation'

Queries URL info

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** | required | URL to query | string | |
**filter** | required | Phish endpoint to query | string | |
**sanitize_url** | optional | Sanitizes provided URL | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.filter | string | | |
action_result.parameter.sanitize_url | boolean | | |
action_result.parameter.url | string | | |
action_result.data.\*.\_embedded.phish.\*.confidence_level | numeric | | |
action_result.data.\*.\_embedded.phish.\*.status | numeric | | |
action_result.data.\*.\_embedded.phish.\*.url | string | `url` | |
action_result.data.\*.total_found | numeric | | |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
