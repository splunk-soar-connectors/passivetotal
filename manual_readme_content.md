[comment]: # ""
[comment]: # "    File: README.md"
[comment]: # "    Copyright (c) 2016-2022 Splunk Inc."
[comment]: # "    Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
[comment]: # ""
For 'domain reputation' and 'ip reputation' actions unique and passive fields of output display data
according to the heatmap available on <https://community.riskiq.com>

## Playbook Backward Compatibility

-   Four new actions 'lookup certificate', 'lookup certificate hash', 'get host pairs', and 'get
    host components' have been added in version 2.1.0. Hence, it is requested to the end-user to
    please update their existing playbooks by inserting the corresponding action blocks for this
    action on the earlier versions of the app.
-   The existing output data paths have been modified and a few new data paths have been added to
    the actions in version 2.3.x. Hence, the end-users are requested to update their existing
    playbooks by re-inserting | modifying | deleting the corresponding action blocks to ensure the
    correct functioning of the playbooks created on the earlier versions of the app.

## Known Issue

-   In the 'lookup certificate' action when we pass 'serialNumber' in the field and a valid value in
    the query(field value), it returns an empty result array which should not be the case as we can
    see the results for the same on the UI. Reported issue
    [here](https://github.com/passivetotal/python_api/issues/23)

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the PassiveTotal server. Below are the
default ports used by Splunk SOAR.

| SERVICE NAME | TRANSPORT PROTOCOL | PORT |
|--------------|--------------------|------|
| **http**     | tcp                | 80   |
| **https**    | tcp                | 443  |
