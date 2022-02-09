[comment]: # "Auto-generated SOAR connector documentation"
# PassiveTotal

Publisher: Splunk  
Connector Version: 2\.3\.1  
Product Vendor: PassiveTotal  
Product Name: PassiveTotal  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.1\.0  

This app implements investigative actions by integrating with the PassiveTotal cloud reputation service

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
    playbooks by re-inserting \| modifying \| deleting the corresponding action blocks to ensure the
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


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a PassiveTotal asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**key** |  required  | string | API user key \(email\)
**secret** |  required  | password | API secret

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[domain reputation](#action-domain-reputation) - Get domain information/reputation  
[ip reputation](#action-ip-reputation) - Get IP information/reputation   
[whois ip](#action-whois-ip) - Get IP WHOIS information  
[whois domain](#action-whois-domain) - Get domain WHOIS information  
[lookup certificate hash](#action-lookup-certificate-hash) - Lookup certificate by hash  
[lookup certificate](#action-lookup-certificate) - Lookup certificate  
[get host components](#action-get-host-components) - Retrieves the host attribute components of a query  
[get host pairs](#action-get-host-pairs) - Retrieves the host attribute pairs related to the query  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'domain reputation'
Get domain information/reputation

Type: **investigate**  
Read only: **True**

Passive information about a domain could get very large, because of which the calls could timeout\. Use the <b>from</b> and <b>to</b> parameters to limit the passive data to query between a time range\. If <b>from</b> parameter is not specified, the action gets data for the past 30 days\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string |  `domain`  `url` 
**from** |  optional  | The start date for Passive data \(YYYY\-MM\-DD\) | string | 
**to** |  optional  | The end date for Passive data \(YYYY\-MM\-DD\) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.domain | string |  `domain`  `url` 
action\_result\.parameter\.from | string | 
action\_result\.parameter\.to | string | 
action\_result\.data\.\*\.classification\.classification | string | 
action\_result\.data\.\*\.ever\_compromised | boolean | 
action\_result\.data\.\*\.metadata\.autonomousSystemName | string | 
action\_result\.data\.\*\.metadata\.autonomousSystemNumber | string | 
action\_result\.data\.\*\.metadata\.classification | string | 
action\_result\.data\.\*\.metadata\.country | string | 
action\_result\.data\.\*\.metadata\.dynamic | string | 
action\_result\.data\.\*\.metadata\.dynamicDns | boolean | 
action\_result\.data\.\*\.metadata\.everCompromised | boolean | 
action\_result\.data\.\*\.metadata\.global\_tags\.\* | string | 
action\_result\.data\.\*\.metadata\.latitude | string | 
action\_result\.data\.\*\.metadata\.longitude | string | 
action\_result\.data\.\*\.metadata\.network | string | 
action\_result\.data\.\*\.metadata\.primaryDomain | string |  `domain` 
action\_result\.data\.\*\.metadata\.queryType | string | 
action\_result\.data\.\*\.metadata\.queryValue | string | 
action\_result\.data\.\*\.metadata\.sinkhole | boolean | 
action\_result\.data\.\*\.metadata\.subdomains\.\* | string | 
action\_result\.data\.\*\.metadata\.system\_tags\.\* | string | 
action\_result\.data\.\*\.metadata\.tags\.\* | string | 
action\_result\.data\.\*\.metadata\.tld | string | 
action\_result\.data\.\*\.passive\.firstSeen | string | 
action\_result\.data\.\*\.passive\.lastSeen | string | 
action\_result\.data\.\*\.passive\.pager | string | 
action\_result\.data\.\*\.passive\.queryType | string | 
action\_result\.data\.\*\.passive\.queryValue | string | 
action\_result\.data\.\*\.passive\.results\.\*\.collected | string | 
action\_result\.data\.\*\.passive\.results\.\*\.firstSeen | string | 
action\_result\.data\.\*\.passive\.results\.\*\.lastSeen | string | 
action\_result\.data\.\*\.passive\.results\.\*\.recordHash | string |  `sha256` 
action\_result\.data\.\*\.passive\.results\.\*\.recordType | string | 
action\_result\.data\.\*\.passive\.results\.\*\.resolve | string |  `ip`  `passivetotal ipv6` 
action\_result\.data\.\*\.passive\.results\.\*\.resolveType | string | 
action\_result\.data\.\*\.passive\.results\.\*\.source\.\* | string | 
action\_result\.data\.\*\.passive\.results\.\*\.value | string | 
action\_result\.data\.\*\.passive\.totalRecords | numeric | 
action\_result\.data\.\*\.sinkhole | boolean | 
action\_result\.data\.\*\.tags\.\* | string | 
action\_result\.data\.\*\.unique\.\* | string |  `domain` 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.as\_name | string | 
action\_result\.summary\.classification | string | 
action\_result\.summary\.country | string | 
action\_result\.summary\.dynamic\_domain | boolean | 
action\_result\.summary\.ever\_compromised | boolean | 
action\_result\.summary\.first\_seen | string | 
action\_result\.summary\.last\_seen | string | 
action\_result\.summary\.sinkhole | boolean | 
action\_result\.summary\.total\_unique\_domains | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'ip reputation'
Get IP information/reputation 

Type: **investigate**  
Read only: **True**

Passive information about an IP could get very large, resulting in timeouts\. Use the <b>from</b> and <b>to</b> parameters to limit the passive data to query between a time range\. If <b>from</b> parameter is not specified, the action gets data for the past 30 days\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to query | string |  `ip`  `passivetotal ipv6` 
**from** |  optional  | The start date for Passive data \(YYYY\-MM\-DD\) | string | 
**to** |  optional  | The end date for Passive data \(YYYY\-MM\-DD\) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.from | string | 
action\_result\.parameter\.ip | string |  `ip`  `passivetotal ipv6` 
action\_result\.parameter\.to | string | 
action\_result\.data\.\*\.classification\.classification | string | 
action\_result\.data\.\*\.ever\_compromised | boolean | 
action\_result\.data\.\*\.metadata\.autonomousSystemName | string | 
action\_result\.data\.\*\.metadata\.autonomousSystemNumber | numeric | 
action\_result\.data\.\*\.metadata\.classification | string | 
action\_result\.data\.\*\.metadata\.country | string | 
action\_result\.data\.\*\.metadata\.dynamic | string | 
action\_result\.data\.\*\.metadata\.dynamicDns | boolean | 
action\_result\.data\.\*\.metadata\.everCompromised | boolean | 
action\_result\.data\.\*\.metadata\.global\_tags\.\* | string | 
action\_result\.data\.\*\.metadata\.latitude | numeric | 
action\_result\.data\.\*\.metadata\.longitude | numeric | 
action\_result\.data\.\*\.metadata\.network | string | 
action\_result\.data\.\*\.metadata\.primaryDomain | string |  `domain` 
action\_result\.data\.\*\.metadata\.queryType | string | 
action\_result\.data\.\*\.metadata\.queryValue | string |  `ip`  `passivetotal ipv6` 
action\_result\.data\.\*\.metadata\.sinkhole | boolean | 
action\_result\.data\.\*\.metadata\.system\_tags\.\* | string | 
action\_result\.data\.\*\.metadata\.tags\.\* | string | 
action\_result\.data\.\*\.metadata\.tld | string | 
action\_result\.data\.\*\.passive\.firstSeen | string | 
action\_result\.data\.\*\.passive\.lastSeen | string | 
action\_result\.data\.\*\.passive\.pager | string | 
action\_result\.data\.\*\.passive\.queryType | string | 
action\_result\.data\.\*\.passive\.queryValue | string |  `ip`  `passivetotal ipv6` 
action\_result\.data\.\*\.passive\.results\.\*\.collected | string | 
action\_result\.data\.\*\.passive\.results\.\*\.firstSeen | string | 
action\_result\.data\.\*\.passive\.results\.\*\.lastSeen | string | 
action\_result\.data\.\*\.passive\.results\.\*\.recordHash | string |  `sha256` 
action\_result\.data\.\*\.passive\.results\.\*\.recordType | string | 
action\_result\.data\.\*\.passive\.results\.\*\.resolve | string | 
action\_result\.data\.\*\.passive\.results\.\*\.resolveType | string | 
action\_result\.data\.\*\.passive\.results\.\*\.source\.\* | string | 
action\_result\.data\.\*\.passive\.results\.\*\.value | string |  `ip`  `passivetotal ipv6` 
action\_result\.data\.\*\.passive\.totalRecords | numeric | 
action\_result\.data\.\*\.sinkhole | boolean | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.firstSeen | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.ipAddresses\.\* | string |  `ip`  `passivetotal ipv6` 
action\_result\.data\.\*\.ssl\_certificates\.\*\.lastSeen | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.tags\.\* | string | 
action\_result\.data\.\*\.unique\.\* | string |  `domain` 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.as\_name | string | 
action\_result\.summary\.classification | string | 
action\_result\.summary\.country | string | 
action\_result\.summary\.dynamic\_domain | boolean | 
action\_result\.summary\.ever\_compromised | boolean | 
action\_result\.summary\.first\_seen | string | 
action\_result\.summary\.last\_seen | string | 
action\_result\.summary\.sinkhole | boolean | 
action\_result\.summary\.total\_unique\_domains | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'whois ip'
Get IP WHOIS information

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to query | string |  `ip`  `passivetotal ipv6` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip | string |  `ip`  `passivetotal ipv6` 
action\_result\.data\.\*\.admin\.city | string | 
action\_result\.data\.\*\.admin\.country | string | 
action\_result\.data\.\*\.admin\.email | string |  `email` 
action\_result\.data\.\*\.admin\.fax | string | 
action\_result\.data\.\*\.admin\.name | string | 
action\_result\.data\.\*\.admin\.organization | string | 
action\_result\.data\.\*\.admin\.postalCode | string | 
action\_result\.data\.\*\.admin\.state | string | 
action\_result\.data\.\*\.admin\.street | string | 
action\_result\.data\.\*\.admin\.telephone | string | 
action\_result\.data\.\*\.contactEmail | string |  `email` 
action\_result\.data\.\*\.domain | string |  `domain`  `ip`  `passivetotal ipv6` 
action\_result\.data\.\*\.expiresAt | string | 
action\_result\.data\.\*\.lastLoadedAt | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.organization | string | 
action\_result\.data\.\*\.rawText | string | 
action\_result\.data\.\*\.registered | string | 
action\_result\.data\.\*\.registrant\.city | string | 
action\_result\.data\.\*\.registrant\.country | string | 
action\_result\.data\.\*\.registrant\.email | string |  `email` 
action\_result\.data\.\*\.registrant\.fax | string | 
action\_result\.data\.\*\.registrant\.name | string | 
action\_result\.data\.\*\.registrant\.organization | string | 
action\_result\.data\.\*\.registrant\.postalCode | string | 
action\_result\.data\.\*\.registrant\.state | string | 
action\_result\.data\.\*\.registrant\.street | string | 
action\_result\.data\.\*\.registrant\.telephone | string | 
action\_result\.data\.\*\.registrar | string | 
action\_result\.data\.\*\.registryUpdatedAt | string | 
action\_result\.data\.\*\.success | boolean | 
action\_result\.data\.\*\.tech\.city | string | 
action\_result\.data\.\*\.tech\.country | string | 
action\_result\.data\.\*\.tech\.email | string |  `email` 
action\_result\.data\.\*\.tech\.fax | string | 
action\_result\.data\.\*\.tech\.name | string | 
action\_result\.data\.\*\.tech\.organization | string | 
action\_result\.data\.\*\.tech\.postalCode | string | 
action\_result\.data\.\*\.tech\.state | string | 
action\_result\.data\.\*\.tech\.street | string | 
action\_result\.data\.\*\.tech\.telephone | string | 
action\_result\.data\.\*\.telephone | string | 
action\_result\.data\.\*\.text | string | 
action\_result\.data\.\*\.whoisServer | string |  `domain` 
action\_result\.data\.\*\.nameServers\.\* | string | 
action\_result\.data\.\*\.zone\.email | string |  `email` 
action\_result\.data\.\*\.zone\.organization | string | 
action\_result\.data\.\*\.zone\.telephone | string | 
action\_result\.data\.\*\.domainStatus | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.city | string | 
action\_result\.summary\.country | string | 
action\_result\.summary\.organization | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'whois domain'
Get domain WHOIS information

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string |  `domain`  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.domain | string |  `domain`  `url` 
action\_result\.data\.\*\.admin\.city | string | 
action\_result\.data\.\*\.admin\.country | string | 
action\_result\.data\.\*\.admin\.email | string |  `email` 
action\_result\.data\.\*\.admin\.fax | string | 
action\_result\.data\.\*\.admin\.name | string | 
action\_result\.data\.\*\.admin\.organization | string | 
action\_result\.data\.\*\.admin\.postalCode | string | 
action\_result\.data\.\*\.admin\.state | string | 
action\_result\.data\.\*\.admin\.street | string | 
action\_result\.data\.\*\.admin\.telephone | string | 
action\_result\.data\.\*\.billing\.country | string | 
action\_result\.data\.\*\.billing\.organization | string | 
action\_result\.data\.\*\.billing\.state | string | 
action\_result\.data\.\*\.contactEmail | string |  `email` 
action\_result\.data\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.expiresAt | string | 
action\_result\.data\.\*\.lastLoadedAt | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.nameServers\.\* | string |  `domain` 
action\_result\.data\.\*\.organization | string | 
action\_result\.data\.\*\.rawText | string | 
action\_result\.data\.\*\.registered | string | 
action\_result\.data\.\*\.registrant\.city | string | 
action\_result\.data\.\*\.registrant\.country | string | 
action\_result\.data\.\*\.registrant\.email | string |  `email` 
action\_result\.data\.\*\.registrant\.fax | string | 
action\_result\.data\.\*\.registrant\.name | string | 
action\_result\.data\.\*\.registrant\.organization | string | 
action\_result\.data\.\*\.registrant\.postalCode | string | 
action\_result\.data\.\*\.registrant\.state | string | 
action\_result\.data\.\*\.registrant\.street | string | 
action\_result\.data\.\*\.registrant\.telephone | string | 
action\_result\.data\.\*\.registrar | string | 
action\_result\.data\.\*\.registryUpdatedAt | string | 
action\_result\.data\.\*\.success | boolean | 
action\_result\.data\.\*\.tech\.city | string | 
action\_result\.data\.\*\.tech\.country | string | 
action\_result\.data\.\*\.tech\.email | string |  `email` 
action\_result\.data\.\*\.tech\.fax | string | 
action\_result\.data\.\*\.tech\.name | string | 
action\_result\.data\.\*\.tech\.organization | string | 
action\_result\.data\.\*\.tech\.postalCode | string | 
action\_result\.data\.\*\.tech\.state | string | 
action\_result\.data\.\*\.tech\.street | string | 
action\_result\.data\.\*\.tech\.telephone | string | 
action\_result\.data\.\*\.telephone | string | 
action\_result\.data\.\*\.text | string | 
action\_result\.data\.\*\.whoisServer | string |  `domain` 
action\_result\.data\.\*\.domainStatus | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.city | string | 
action\_result\.summary\.country | string | 
action\_result\.summary\.organization | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup certificate hash'
Lookup certificate by hash

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | The SHA\-1 hash of the certificate to retrieve | string |  `sha1`  `hash` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.query | string |  `sha1`  `hash` 
action\_result\.data\.\*\.ssl\_certificate\.\*\.sslVersion | string | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.firstSeen | numeric | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.lastSeen | numeric | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.ssl\_certificate\.\*\.issueDate | string | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.fingerprint | string | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.serialNumber | string | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.issuerCountry | string | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.issuerSurname | string | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.expirationDate | string | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.issuerProvince | string | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.subjectCountry | string | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.subjectSurname | string | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.subjectAlternativeNames\.\* | string | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.issuerGivenName | string | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.subjectProvince | string | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.issuerCommonName | string | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.subjectGivenName | string | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.subjectCommonName | string | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.issuerEmailAddress | string | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.issuerLocalityName | string | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.issuerSerialNumber | string | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.issuerStreetAddress | string | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.subjectEmailAddress | string | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.subjectLocalityName | string | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.subjectSerialNumber | string | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.subjectStreetAddress | string | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.issuerOrganizationName | string | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.subjectOrganizationName | string | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.issuerStateOrProvinceName | string | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.issuerOrganizationUnitName | string | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.subjectStateOrProvinceName | string | 
action\_result\.data\.\*\.ssl\_certificate\.\*\.subjectOrganizationUnitName | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.ssl\_certificates\.\*\.lastSeen | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.firstSeen | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.ipAddresses\.\* | string |  `ip`  `passivetotal ipv6` 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.total\_records | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup certificate'
Lookup certificate

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | Field value for which to search certificates | string | 
**field** |  required  | The field for which to search certificates | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.query | string | 
action\_result\.parameter\.field | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.firstSeen | numeric | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.lastSeen | numeric | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.ssl\_certificates\.\*\.issueDate | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.fingerprint | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.serialNumber | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.issuerCountry | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.issuerSurname | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.expirationDate | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.issuerProvince | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.subjectCountry | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.subjectSurname | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.subjectAlternativeNames\.\* | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.issuerGivenName | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.subjectProvince | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.issuerCommonName | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.subjectGivenName | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.subjectCommonName | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.issuerEmailAddress | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.issuerLocalityName | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.issuerSerialNumber | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.issuerStreetAddress | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.subjectEmailAddress | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.subjectLocalityName | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.subjectSerialNumber | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.subjectStreetAddress | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.issuerOrganizationName | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.subjectOrganizationName | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.issuerStateOrProvinceName | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.issuerOrganizationUnitName | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.subjectStateOrProvinceName | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.subjectOrganizationUnitName | string | 
action\_result\.data\.\*\.ssl\_certificates\.\*\.sslVersion | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.total\_records | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get host components'
Retrieves the host attribute components of a query

Type: **investigate**  
Read only: **True**

<p>By default, 2000 records will be fetched per page\. If more data exists, then use the 'page' parameter for pagination\.</p>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | The domain or IP being queried | string | 
**from** |  optional  | The start date for Passive data \(YYYY\-MM\-DD\) | string | 
**to** |  optional  | The end date for Passive data \(YYYY\-MM\-DD\) | string | 
**page** |  optional  | Page number for paging through results, defaults to 0 | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.query | string | 
action\_result\.parameter\.from | string | 
action\_result\.parameter\.to | string | 
action\_result\.parameter\.page | numeric | 
action\_result\.data\.\*\.components\.\*\.label | string | 
action\_result\.data\.\*\.components\.\*\.version | string | 
action\_result\.data\.\*\.components\.\*\.category | string | 
action\_result\.data\.\*\.components\.\*\.hostname | string | 
action\_result\.data\.\*\.components\.\*\.address | string | 
action\_result\.data\.\*\.components\.\*\.lastSeen | string | 
action\_result\.data\.\*\.components\.\*\.firstSeen | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.total\_records | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get host pairs'
Retrieves the host attribute pairs related to the query

Type: **investigate**  
Read only: **True**

<p>By default, 2000 records will be fetched per page\. If more data exists, then use the 'page' parameter for pagination\.</p>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | The domain or IP being queried | string | 
**direction** |  required  | The directionality of the search | string | 
**from** |  optional  | The start date for Passive data \(YYYY\-MM\-DD\) | string | 
**to** |  optional  | The end date for Passive data \(YYYY\-MM\-DD\) | string | 
**page** |  optional  | Page number for paging through results, defaults to 0 | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.query | string | 
action\_result\.parameter\.direction | string | 
action\_result\.parameter\.from | string | 
action\_result\.parameter\.to | string | 
action\_result\.parameter\.page | numeric | 
action\_result\.data\.\*\.pairs\.\*\.cause | string | 
action\_result\.data\.\*\.pairs\.\*\.child | string | 
action\_result\.data\.\*\.pairs\.\*\.parent | string | 
action\_result\.data\.\*\.pairs\.\*\.lastSeen | string | 
action\_result\.data\.\*\.pairs\.\*\.firstSeen | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.total\_records | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 