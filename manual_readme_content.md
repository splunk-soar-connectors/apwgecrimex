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
