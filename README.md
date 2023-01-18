[comment]: # "Auto-generated SOAR connector documentation"
# APWG eCrime Exchange

Publisher: Splunk Community  
Connector Version: 1\.0\.1  
Product Vendor: APWG  
Product Name: eCrimeX  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.4\.0  

APWG eCrime Exchange connector

[comment]: # "File: README.md"
[comment]: # "Copyright (c) 2023 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
The purpose of this app to to query urls to determine if they are present in the APWG database.

The filters determine how the url is looked up in the database.

-   URL_exact - query the database exactly with the url provided
-   domain - query the database using only the domain of the url
-   url - query the database using everything before the path of the url. This will return many
    results if https:// or any other common URL components are included

Sanitize_url - removes the path of the url, this is to exclude any sensitive information that might
be in the the url. Note: THIS DOES NOT WORK WITH URL_exact


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a eCrimeX asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**Authorization Key** |  required  | password | API Key for eCrimeX

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[url reputation](#action-url-reputation) - Queries URL info  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'url reputation'
Queries URL info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to query | string | 
**filter** |  required  | Phish endpoint to query | string | 
**sanitize\_url** |  optional  | Sanitizes provided URL | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.filter | string | 
action\_result\.parameter\.sanitize\_url | boolean | 
action\_result\.parameter\.url | string | 
action\_result\.data\.\*\.\_embedded\.phish\.\*\.confidence\_level | numeric | 
action\_result\.data\.\*\.\_embedded\.phish\.\*\.status | numeric | 
action\_result\.data\.\*\.\_embedded\.phish\.\*\.url | string |  `url` 
action\_result\.data\.\*\.total\_found | numeric | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 