[comment]: # "Auto-generated SOAR connector documentation"
# PassiveTotal

Publisher: Splunk  
Connector Version: 2.3.1  
Product Vendor: PassiveTotal  
Product Name: PassiveTotal  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 5.1.0  

This app implements investigative actions by integrating with the PassiveTotal cloud reputation service

[comment]: # ""
[comment]: # "    File: README.md"
[comment]: # "    Copyright (c) 2016-2023 Splunk Inc."
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


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a PassiveTotal asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**key** |  required  | string | API user key (email)
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

Passive information about a domain could get very large, because of which the calls could timeout. Use the <b>from</b> and <b>to</b> parameters to limit the passive data to query between a time range. If <b>from</b> parameter is not specified, the action gets data for the past 30 days.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string |  `domain`  `url` 
**from** |  optional  | The start date for Passive data (YYYY-MM-DD) | string | 
**to** |  optional  | The end date for Passive data (YYYY-MM-DD) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.domain | string |  `domain`  `url`  |   abc.com 
action_result.parameter.from | string |  |   2018-08-01 
action_result.parameter.to | string |  |   2018-10-01 
action_result.data.\*.classification.classification | string |  |   malicious 
action_result.data.\*.ever_compromised | boolean |  |   False  True 
action_result.data.\*.metadata.autonomousSystemName | string |  |   Abc Inc. 
action_result.data.\*.metadata.autonomousSystemNumber | string |  |   56320-57343 
action_result.data.\*.metadata.classification | string |  |   malicious 
action_result.data.\*.metadata.country | string |  |   us 
action_result.data.\*.metadata.dynamic | string |  |  
action_result.data.\*.metadata.dynamicDns | boolean |  |   False  True 
action_result.data.\*.metadata.everCompromised | boolean |  |   False  True 
action_result.data.\*.metadata.global_tags.\* | string |  |   alexa_top_10k 
action_result.data.\*.metadata.latitude | string |  |   37.3 
action_result.data.\*.metadata.longitude | string |  |   -133 
action_result.data.\*.metadata.network | string |  |   1.1.1.0/24 
action_result.data.\*.metadata.primaryDomain | string |  `domain`  |   abc.com 
action_result.data.\*.metadata.queryType | string |  |   domain 
action_result.data.\*.metadata.queryValue | string |  |   abc.com 
action_result.data.\*.metadata.sinkhole | boolean |  |   True  False 
action_result.data.\*.metadata.subdomains.\* | string |  |   zz-tr 
action_result.data.\*.metadata.system_tags.\* | string |  |   hashes 
action_result.data.\*.metadata.tags.\* | string |  |   alexa_top_10k 
action_result.data.\*.metadata.tld | string |  |   .com 
action_result.data.\*.passive.firstSeen | string |  |   2018-08-08 15:47:02 
action_result.data.\*.passive.lastSeen | string |  |   2018-09-01 02:49:36 
action_result.data.\*.passive.pager | string |  |  
action_result.data.\*.passive.queryType | string |  |   domain 
action_result.data.\*.passive.queryValue | string |  |   abc.com 
action_result.data.\*.passive.results.\*.collected | string |  |   2018-10-29 06:59:57 
action_result.data.\*.passive.results.\*.firstSeen | string |  |   2018-09-01 02:49:36 
action_result.data.\*.passive.results.\*.lastSeen | string |  |   2018-09-01 02:49:36 
action_result.data.\*.passive.results.\*.recordHash | string |  `sha256`  |   c37888add095d26003003939c5f6edb6d9450e296b05cfb8137f282c35b57952 
action_result.data.\*.passive.results.\*.recordType | string |  |   A 
action_result.data.\*.passive.results.\*.resolve | string |  `ip`  `passivetotal ipv6`  |   199.59.100.136 
action_result.data.\*.passive.results.\*.resolveType | string |  |   ip 
action_result.data.\*.passive.results.\*.source.\* | string |  |   riskiq 
action_result.data.\*.passive.results.\*.value | string |  |   abc.com 
action_result.data.\*.passive.totalRecords | numeric |  |   4 
action_result.data.\*.sinkhole | boolean |  |   True  False 
action_result.data.\*.tags.\* | string |  |   alexa_top_10k 
action_result.data.\*.unique.\* | string |  `domain`  |   199.59.100.136 
action_result.status | string |  |   success  failed 
action_result.message | string |  |   Total unique domains: 4, Dynamic domain: False, Classification: None, Sinkhole: None, First seen: 2018-08-08 15:47:02, Ever compromised: False, Last seen: 2018-09-01 02:49:36 
action_result.summary.as_name | string |  |   Abc, Inc. 
action_result.summary.classification | string |  |   malicious 
action_result.summary.country | string |  |   us 
action_result.summary.dynamic_domain | boolean |  |   False  True 
action_result.summary.ever_compromised | boolean |  |   False  True 
action_result.summary.first_seen | string |  |   2018-08-08 15:47:02 
action_result.summary.last_seen | string |  |   2018-09-01 02:49:36 
action_result.summary.sinkhole | boolean |  |   False  True 
action_result.summary.total_unique_domains | numeric |  |   4 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'ip reputation'
Get IP information/reputation 

Type: **investigate**  
Read only: **True**

Passive information about an IP could get very large, resulting in timeouts. Use the <b>from</b> and <b>to</b> parameters to limit the passive data to query between a time range. If <b>from</b> parameter is not specified, the action gets data for the past 30 days.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to query | string |  `ip`  `passivetotal ipv6` 
**from** |  optional  | The start date for Passive data (YYYY-MM-DD) | string | 
**to** |  optional  | The end date for Passive data (YYYY-MM-DD) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.from | string |  |   2018-08-01 
action_result.parameter.ip | string |  `ip`  `passivetotal ipv6`  |   1.1.1.1 
action_result.parameter.to | string |  |   2018-10-01 
action_result.data.\*.classification.classification | string |  |   malicious 
action_result.data.\*.ever_compromised | boolean |  |   False  True 
action_result.data.\*.metadata.autonomousSystemName | string |  |   Abc Inc. 
action_result.data.\*.metadata.autonomousSystemNumber | numeric |  |   56320 
action_result.data.\*.metadata.classification | string |  |   malicious 
action_result.data.\*.metadata.country | string |  |   US 
action_result.data.\*.metadata.dynamic | string |  |  
action_result.data.\*.metadata.dynamicDns | boolean |  |   False  True 
action_result.data.\*.metadata.everCompromised | boolean |  |   False  True 
action_result.data.\*.metadata.global_tags.\* | string |  |   Abc 
action_result.data.\*.metadata.latitude | numeric |  |   37.3 
action_result.data.\*.metadata.longitude | numeric |  |   -122.0008 
action_result.data.\*.metadata.network | string |  |   1.1.1.0/24 
action_result.data.\*.metadata.primaryDomain | string |  `domain`  |   abc.com 
action_result.data.\*.metadata.queryType | string |  |   ip 
action_result.data.\*.metadata.queryValue | string |  `ip`  `passivetotal ipv6`  |   1.1.1.1 
action_result.data.\*.metadata.sinkhole | boolean |  |   False  True 
action_result.data.\*.metadata.system_tags.\* | string |  |   routable 
action_result.data.\*.metadata.tags.\* | string |  |   alexa_top_10k 
action_result.data.\*.metadata.tld | string |  |   .com 
action_result.data.\*.passive.firstSeen | string |  |   2018-09-29 00:00:00 
action_result.data.\*.passive.lastSeen | string |  |   2018-10-28 23:48:00 
action_result.data.\*.passive.pager | string |  |  
action_result.data.\*.passive.queryType | string |  |   ip 
action_result.data.\*.passive.queryValue | string |  `ip`  `passivetotal ipv6`  |   1.1.1.1 
action_result.data.\*.passive.results.\*.collected | string |  |   2018-10-29 06:55:51 
action_result.data.\*.passive.results.\*.firstSeen | string |  |   2018-09-30 14:00:00 
action_result.data.\*.passive.results.\*.lastSeen | string |  |   2018-09-30 14:01:32 
action_result.data.\*.passive.results.\*.recordHash | string |  `sha256`  |   72be28ddd4638821d24006c1919fe785e07107d5a6cb8b0e059fd214e0a2580f 
action_result.data.\*.passive.results.\*.recordType | string |  |   A 
action_result.data.\*.passive.results.\*.resolve | string |  |   pop.revistadecorar.com.br 
action_result.data.\*.passive.results.\*.resolveType | string |  |   domain 
action_result.data.\*.passive.results.\*.source.\* | string |  |   riskiq 
action_result.data.\*.passive.results.\*.value | string |  `ip`  `passivetotal ipv6`  |   1.1.1.1 
action_result.data.\*.passive.totalRecords | numeric |  |   89 
action_result.data.\*.sinkhole | boolean |  |   False  True 
action_result.data.\*.ssl_certificates.\*.firstSeen | string |  |   2018-10-22 
action_result.data.\*.ssl_certificates.\*.ipAddresses.\* | string |  `ip`  `passivetotal ipv6`  |   1.1.1.1 
action_result.data.\*.ssl_certificates.\*.lastSeen | string |  |   2018-10-26 
action_result.data.\*.ssl_certificates.\*.sha1 | string |  `sha1`  |   66b27f920b738b8ebbb3cf509201f8a2b7d0152c 
action_result.data.\*.tags.\* | string |  |   Abc 
action_result.data.\*.unique.\* | string |  `domain`  |   cellinicapital.com.au 
action_result.status | string |  |   success  failed 
action_result.message | string |  |   Total unique domains: 123, Classification: None, Sinkhole: False, Country: US, First seen: 2018-09-29 00:00:00, Ever compromised: False, As name: Abc Inc., Last seen: 2018-10-28 23:48:35 
action_result.summary.as_name | string |  |   Abc Inc. 
action_result.summary.classification | string |  |   malicious 
action_result.summary.country | string |  |   US 
action_result.summary.dynamic_domain | boolean |  |   False  True 
action_result.summary.ever_compromised | boolean |  |   False  True 
action_result.summary.first_seen | string |  |   2018-09-29 00:00:00 
action_result.summary.last_seen | string |  |   2018-10-28 23:48:37 
action_result.summary.sinkhole | boolean |  |   False  True 
action_result.summary.total_unique_domains | numeric |  |   123 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'whois ip'
Get IP WHOIS information

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to query | string |  `ip`  `passivetotal ipv6` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ip | string |  `ip`  `passivetotal ipv6`  |   1.1.1.1 
action_result.data.\*.admin.city | string |  |   San Francisco 
action_result.data.\*.admin.country | string |  |   us 
action_result.data.\*.admin.email | string |  `email`  |   domain@abc.com 
action_result.data.\*.admin.fax | string |  |   16500034800 
action_result.data.\*.admin.name | string |  |   Domain Administrator 
action_result.data.\*.admin.organization | string |  |   Abc, Inc. 
action_result.data.\*.admin.postalCode | string |  |   94000 
action_result.data.\*.admin.state | string |  |   ca 
action_result.data.\*.admin.street | string |  |   270 Brannan St, 
action_result.data.\*.admin.telephone | string |  |   16505004800 
action_result.data.\*.contactEmail | string |  `email`  |   test-network@abc.com 
action_result.data.\*.domain | string |  `domain`  `ip`  `passivetotal ipv6`  |   1.1.1.0 
action_result.data.\*.expiresAt | string |  |   2025-03-01T21:00:00.000-0700 
action_result.data.\*.lastLoadedAt | string |  |   2018-06-01T10:35:52.694-0700 
action_result.data.\*.name | string |  |   N/A 
action_result.data.\*.organization | string |  |   Abc Inc. 
action_result.data.\*.rawText | string |  |   Registrar: Handle: 281209_DOMAIN_COM-VRSN LDH Name: domain.com Nameserver: LDH Name: ns1.p31.dynect.net Event: Action: last changed Date: 2013-10-10T17:33:04Z Status: active Nameserver: LDH 
action_result.data.\*.registered | string |  |   2014-03-01T00:00:00.000-0700 
action_result.data.\*.registrant.city | string |  |   San Francisco 
action_result.data.\*.registrant.country | string |  |   us 
action_result.data.\*.registrant.email | string |  `email`  |   domain@abc.com 
action_result.data.\*.registrant.fax | string |  |   16500034800 
action_result.data.\*.registrant.name | string |  |   Domain Administrator 
action_result.data.\*.registrant.organization | string |  |   Abc, Inc. 
action_result.data.\*.registrant.postalCode | string |  |   94107 
action_result.data.\*.registrant.state | string |  |   ca 
action_result.data.\*.registrant.street | string |  |   270 Brannan St, 
action_result.data.\*.registrant.telephone | string |  |   16500034800 
action_result.data.\*.registrar | string |  |   Administered by ARIN 
action_result.data.\*.registryUpdatedAt | string |  |   1991-11-01T00:00:00.000-0800 
action_result.data.\*.success | boolean |  |   False  True 
action_result.data.\*.tech.city | string |  |   San Francisco 
action_result.data.\*.tech.country | string |  |   us 
action_result.data.\*.tech.email | string |  `email`  |   domain@abc.com 
action_result.data.\*.tech.fax | string |  |   16500034800 
action_result.data.\*.tech.name | string |  |   Domain Administrator 
action_result.data.\*.tech.organization | string |  |   Abc, Inc. 
action_result.data.\*.tech.postalCode | string |  |   94000 
action_result.data.\*.tech.state | string |  |   ca 
action_result.data.\*.tech.street | string |  |   270 Brannan St, 
action_result.data.\*.tech.telephone | string |  |   16500034800 
action_result.data.\*.telephone | string |  |   N/A 
action_result.data.\*.text | string |  |   % IANA TEST server
% for more information on IANA, visit http://www.iana.org
% This query returned 1 object

refer:        test.arin.net

inetnum:      8.0.0.0 - 8.255.255.255
organisation: Administered by ARIN
status:       LEGACY

test:        test.arin.net

changed:      1992-12
source:       IANA



NetRange:       1.1.1.0 - 1.1.1.255
CIDR:           1.1.1.0/24
NetName:        LVLT-SPL-1-1-1
NetHandle:      NET-1-1-1-0-1
Parent:         LVLT-ORG-1-1 (NET-1-0-0-0-1)
NetType:        Reallocated
OriginAS:       
Organization:   Abc Inc. (SPL)
RegDate:        2014-03-01
Updated:        2014-03-01
Ref:            https://test.arin.net/rest/net/NET-1-1-1-0-1



OrgName:        Abc Inc.
OrgId:          Spl
Address:        270 Brannan St
City:           San Francisco
StateProv:      CA
PostalCode:     94107
Country:        US
RegDate:        2000-04-30
Updated:        2017-12-01
Ref:            https://test.arin.net/rest/org/SPL


OrgTechHandle: ZG00-ARIN
OrgTechName:   Abc Inc.
OrgTechPhone:  +1-650-000-0000 
OrgTechEmail:  arin-contact@abc.com
OrgTechRef:    https://test.arin.net/rest/poc/ZG00-ARIN

OrgAbuseHandle: ABUSE5200-ARIN
OrgAbuseName:   Abuse
OrgAbusePhone:  +1-650-000-0000 
OrgAbuseEmail:  test-network@abc.com
OrgAbuseRef:    https://test.arin.net/rest/poc/ABUSE5200-ARIN

 
action_result.data.\*.whoisServer | string |  `domain`  |   test.arin.net 
action_result.data.\*.nameServers.\* | string |  |  
action_result.data.\*.zone.email | string |  `email`  |  
action_result.data.\*.zone.organization | string |  |   Abc, Inc. 
action_result.data.\*.zone.telephone | string |  |   N/A 
action_result.data.\*.domainStatus | string |  |   active 
action_result.status | string |  |   success  failed 
action_result.message | string |  |   City: San Francisco, Country: US, Organization: Abc Inc. 
action_result.summary.city | string |  |   San Francisco 
action_result.summary.country | string |  |   US 
action_result.summary.organization | string |  |   Abc Inc. 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'whois domain'
Get domain WHOIS information

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string |  `domain`  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.domain | string |  `domain`  `url`  |   abc.com 
action_result.data.\*.admin.city | string |  |   San Francisco 
action_result.data.\*.admin.country | string |  |   us 
action_result.data.\*.admin.email | string |  `email`  |   domain@abc.com 
action_result.data.\*.admin.fax | string |  |   16500034800 
action_result.data.\*.admin.name | string |  |   Domain Administrator 
action_result.data.\*.admin.organization | string |  |   Abc, Inc. 
action_result.data.\*.admin.postalCode | string |  |   94000 
action_result.data.\*.admin.state | string |  |   ca 
action_result.data.\*.admin.street | string |  |   270 Brannan St, 
action_result.data.\*.admin.telephone | string |  |   16505004800 
action_result.data.\*.billing.country | string |  |   us 
action_result.data.\*.billing.organization | string |  |   Organization Name 
action_result.data.\*.billing.state | string |  |   ca 
action_result.data.\*.contactEmail | string |  `email`  |   domain@abc.com 
action_result.data.\*.domain | string |  `domain`  |   abc.com 
action_result.data.\*.expiresAt | string |  |   2025-03-01T21:00:00.000-0700 
action_result.data.\*.lastLoadedAt | string |  |   2018-06-01T00:40:39.503-0700 
action_result.data.\*.name | string |  |   Domain Administrator 
action_result.data.\*.nameServers.\* | string |  `domain`  |   b.ns.abc.com 
action_result.data.\*.organization | string |  |   Abc, Inc. 
action_result.data.\*.rawText | string |  |   Registrar: Handle: 281209_DOMAIN_COM-VRSN LDH Name: domain.com Nameserver: LDH Name: ns1.p31.dynect.net Event: Action: last changed Date: 2013-10-10T17:33:04Z Status: active Nameserver: LDH 
action_result.data.\*.registered | string |  |   1997-03-01T21:00:00.000-0800 
action_result.data.\*.registrant.city | string |  |   San Francisco 
action_result.data.\*.registrant.country | string |  |   us 
action_result.data.\*.registrant.email | string |  `email`  |   domain@abc.com 
action_result.data.\*.registrant.fax | string |  |   16500034800 
action_result.data.\*.registrant.name | string |  |   Domain Administrator 
action_result.data.\*.registrant.organization | string |  |   Abc, Inc. 
action_result.data.\*.registrant.postalCode | string |  |   94107 
action_result.data.\*.registrant.state | string |  |   ca 
action_result.data.\*.registrant.street | string |  |   270 Brannan St, 
action_result.data.\*.registrant.telephone | string |  |   16500034800 
action_result.data.\*.registrar | string |  |   TestMonitor Inc. 
action_result.data.\*.registryUpdatedAt | string |  |   2016-11-01T12:28:07.000-0800 
action_result.data.\*.success | boolean |  |   False  True 
action_result.data.\*.tech.city | string |  |   San Francisco 
action_result.data.\*.tech.country | string |  |   us 
action_result.data.\*.tech.email | string |  `email`  |   domain@abc.com 
action_result.data.\*.tech.fax | string |  |   16500034800 
action_result.data.\*.tech.name | string |  |   Domain Administrator 
action_result.data.\*.tech.organization | string |  |   Abc, Inc. 
action_result.data.\*.tech.postalCode | string |  |   94000 
action_result.data.\*.tech.state | string |  |   ca 
action_result.data.\*.tech.street | string |  |   270 Brannan St, 
action_result.data.\*.tech.telephone | string |  |   16500034800 
action_result.data.\*.telephone | string |  |   16505004800 
action_result.data.\*.text | string |  |   Domain Name: ABC.COM
   Registry Domain ID: 1000008_DOMAIN_COM-TESTRSN
   Registrar TEST Server: test.testmonitor.com
   Registrar URL: http://www.testmonitor.com
   Updated Date: 2016-11-29T20:28:07Z
   Creation Date: 1997-03-29T05:00:00Z
   Registry Expiry Date: 2025-03-30T04:00:00Z
   Registrar: TestMonitor Inc.
   Registrar IANA ID: 292
   Registrar Abuse Contact Email: abusecomplaints@testmonitor.com
   Registrar Abuse Contact Phone: +1.2083895740
   Domain Status: clientDeleteProhibited https://testcann.org/epp#clientDeleteProhibited
   Domain Status: clientTransferProhibited https://testcann.org/epp#clientTransferProhibited
   Domain Status: clientUpdateProhibited https://testcann.org/epp#clientUpdateProhibited
   Domain Status: serverDeleteProhibited https://testcann.org/epp#serverDeleteProhibited
   Domain Status: serverTransferProhibited https://testcann.org/epp#serverTransferProhibited
   Domain Status: serverUpdateProhibited https://testcann.org/epp#serverUpdateProhibited
   Name Server: A.NS.ABC.COM
   Name Server: B.NS.ABC.COM
   DNSSEC: unsigned
   URL of the TESTCANN Test Inaccuracy Complaint Form: https://www.testcann.org/wicf/
>>> Last update of test database: 2018-06-22T07:40:22Z <<<

For more information on Test status codes, please visit https://testcann.org/epp

NOTICE: The expiration date displayed in this record is the date the
registrar's sponsorship of the domain name registration in the registry is
currently set to expire. This date does not necessarily reflect the expiration
date of the domain name registrant's agreement with the sponsoring
registrar.  Users may consult the sponsoring registrar's Test database to
view the registrar's reported date of expiration for this registration.

TERMS OF USE: You are not authorized to access or query our Test
database through the use of electronic processes that are high-volume and
automated except as reasonably necessary to register domain names or
modify existing registrations; the Data in TestSign Global Registry
Services' ("TestSign") Test database is provided by TestSign for
information purposes only, and to assist persons in obtaining information
about or related to a domain name registration record. TestSign does not
guarantee its accuracy. By submitting a Test query, you agree to abide
by the following terms of use: You agree that you may use this Data only
for lawful purposes and that under no circumstances will you use this Data
to: (1) allow, enable, or otherwise support the transmission of mass
unsolicited, commercial advertising or solicitations via e-mail, telephone,
or facsimile; or (2) enable high volume, automated, electronic processes
that apply to TestSign (or its computer systems). The compilation,
repackaging, dissemination or other use of this Data is expressly
prohibited without the prior written consent of TestSign. You agree not to
use electronic processes that are automated and high-volume to access or
query the Test database except as reasonably necessary to register
domain names or modify existing registrations. TestSign reserves the right
to restrict your access to the Test database in its sole discretion to ensure
operational stability.  TestSign may restrict or terminate your access to the
Test database for failure to abide by these terms of use. TestSign
reserves the right to modify these terms at any time.

The Registry database contains ONLY .COM, .NET, .EDU domains and
Registrars.

Domain Name: abc.com
Registry Domain ID: 2320948_DOMAIN_COM-TESTRSN
Registrar TEST Server: test.testmonitor.com
Registrar URL: http://www.testmonitor.com
Updated Date: 2016-11-29T12:28:07-0800
Creation Date: 1997-03-28T21:00:00-0800
Registrar Registration Expiration Date: 2025-03-29T00:00:00-0700
Registrar: TestMonitor, Inc.
Registrar IANA ID: 292
Registrar Abuse Contact Email: abusecomplaints@testmonitor.com
Registrar Abuse Contact Phone: +1.2000895740
Domain Status: clientUpdateProhibited (https://www.testcann.org/epp#clientUpdateProhibited)
Domain Status: clientTransferProhibited (https://www.testcann.org/epp#clientTransferProhibited)
Domain Status: clientDeleteProhibited (https://www.testcann.org/epp#clientDeleteProhibited)
Domain Status: serverUpdateProhibited (https://www.testcann.org/epp#serverUpdateProhibited)
Domain Status: serverTransferProhibited (https://www.testcann.org/epp#serverTransferProhibited)
Domain Status: serverDeleteProhibited (https://www.testcann.org/epp#serverDeleteProhibited)
Registry Registrant ID: 
Registrant Name: Domain Administrator
Registrant Organization: Abc, Inc.
Registrant Street: 270 Brannan St, 
Registrant City: San Francisco
Registrant State/Province: CA
Registrant Postal Code: 94107
Registrant Country: US
Registrant Phone: +1.6500034800
Registrant Phone Ext: 
Registrant Fax: +1.6500034800
Registrant Fax Ext: 
Registrant Email: domain@abc.com
Registry Admin ID: 
Admin Name: Domain Administrator
Admin Organization: Abc, Inc.
Admin Street: 270 Brannan St, 
Admin City: San Francisco
Admin State/Province: CA
Admin Postal Code: 94107
Admin Country: US
Admin Phone: +1.6500034800
Admin Phone Ext: 
Admin Fax: +1.6500034800
Admin Fax Ext: 
Admin Email: domain@abc.com
Registry Tech ID: 
Tech Name: Domain Administrator
Tech Organization: Abc, Inc.
Tech Street: 270 Brannan St, 
Tech City: San Francisco
Tech State/Province: CA
Tech Postal Code: 94107
Tech Country: US
Tech Phone: +1.6500034800
Tech Phone Ext: 
Tech Fax: +1.6500034800
Tech Fax Ext: 
Tech Email: domain@abc.com
Name Server: b.ns.abc.com
Name Server: a.ns.abc.com
DNSSEC: unsigned
URL of the TESTCANN TEST Data Problem Reporting System: http://testdprs.internic.net/
>>> Last update of TEST database: 2018-06-22T00:35:57-0700 <<<

If certain contact information is not shown for a Registrant, Administrative,
or Technical contact, and you wish to send a message to these contacts, please
send your message to relay@testmonitor.com and specify the domain name in
the subject line. We will forward that message to the underlying contact.

If you have a legitimate interest in viewing the non-public TEST details, send
your request and the reasons for your request to abusecomplaints@testmonitor.com
and specify the domain name in the subject line. We will review that request and
may ask for supporting documentation and explanation.

The Data in TestMonitor.com's TEST database is provided by TestMonitor.com for
information purposes, and to assist persons in obtaining information about or
related to a domain name registration record.  TestMonitor.com does not guarantee
its accuracy.  By submitting a TEST query, you agree that you will use this Data
only for lawful purposes and that, under no circumstances will you use this Data to:
 (1) allow, enable, or otherwise support the transmission of mass unsolicited,
     commercial advertising or solicitations via e-mail (spam); or
 (2) enable high volume, automated, electronic processes that apply to
     TestMonitor.com (or its systems).
TestMonitor.com reserves the right to modify these terms at any time.
By submitting this query, you agree to abide by this policy.

TestMonitor is the Global Leader in Online Brand Protection.

TestMonitor Domain Management(TM)
TestMonitor Brand Protection(TM)
TestMonitor AntiPiracy(TM)
TestMonitor AntiFraud(TM)
Professional and Managed Services

Visit TestMonitor at http://www.testmonitor.com
Contact us at +1.8007459229
In Europe, at +44.02032062220

For more information on Test status codes, please visit
 https://www.testcann.org/resources/pages/epp-status-codes-2014-06-16-en
---- 
action_result.data.\*.whoisServer | string |  `domain`  |   test.testmonitor.com 
action_result.data.\*.domainStatus | string |  |   delete prohibited,transfer prohibited,renew prohibited,update prohibited 
action_result.status | string |  |   success  failed 
action_result.message | string |  |   City: San Francisco, Country: us, Organization: Abc, Inc. 
action_result.summary.city | string |  |   San Francisco 
action_result.summary.country | string |  |   us 
action_result.summary.organization | string |  |   Abc, Inc. 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'lookup certificate hash'
Lookup certificate by hash

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | The SHA-1 hash of the certificate to retrieve | string |  `sha1`  `hash` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.query | string |  `sha1`  `hash`  |   cf23df2207d99a74fbe169e3eba035e633b65d94 
action_result.data.\*.ssl_certificate.\*.sslVersion | string |  |   3 
action_result.data.\*.ssl_certificate.\*.firstSeen | numeric |  |   1450684800000 
action_result.data.\*.ssl_certificate.\*.lastSeen | numeric |  |   1450684800000 
action_result.data.\*.ssl_certificate.\*.sha1 | string |  `sha1`  |   240461b20dbb24a61b0a986821c2ad01bd3a8522 
action_result.data.\*.ssl_certificate.\*.issueDate | string |  |   2020-01-03 
action_result.data.\*.ssl_certificate.\*.fingerprint | string |  |   f2:28:ea:c5:3f:8e:45:4f:32:d2:a6:12:73:18:9f:d1:92:32:8f:c9 
action_result.data.\*.ssl_certificate.\*.serialNumber | string |  |   2475382717063105701088747457914605763880288261 
action_result.data.\*.ssl_certificate.\*.issuerCountry | string |  |   US 
action_result.data.\*.ssl_certificate.\*.issuerSurname | string |  |   Surname 
action_result.data.\*.ssl_certificate.\*.expirationDate | string |  |   Jan 09 17:59:21 2035 GMT 
action_result.data.\*.ssl_certificate.\*.issuerProvince | string |  |   Province Name 
action_result.data.\*.ssl_certificate.\*.subjectCountry | string |  |   US 
action_result.data.\*.ssl_certificate.\*.subjectSurname | string |  |   Surname 
action_result.data.\*.ssl_certificate.\*.subjectAlternativeNames.\* | string |  |  
action_result.data.\*.ssl_certificate.\*.issuerGivenName | string |  |   Xpress 
action_result.data.\*.ssl_certificate.\*.subjectProvince | string |  |   Province Name 
action_result.data.\*.ssl_certificate.\*.issuerCommonName | string |  |   Let's Encrypt Authority X3 
action_result.data.\*.ssl_certificate.\*.subjectGivenName | string |  |   luxavate.com 
action_result.data.\*.ssl_certificate.\*.subjectCommonName | string |  |   luxavate.com 
action_result.data.\*.ssl_certificate.\*.issuerEmailAddress | string |  |   abc@gmail.com 
action_result.data.\*.ssl_certificate.\*.issuerLocalityName | string |  |   Issuer Locality 
action_result.data.\*.ssl_certificate.\*.issuerSerialNumber | string |  |   8571006865812752217367962054313612264 
action_result.data.\*.ssl_certificate.\*.issuerStreetAddress | string |  |   270 Brannan St, 
action_result.data.\*.ssl_certificate.\*.subjectEmailAddress | string |  |   abc@gmail.com 
action_result.data.\*.ssl_certificate.\*.subjectLocalityName | string |  |   Subject Locality 
action_result.data.\*.ssl_certificate.\*.subjectSerialNumber | string |  |   8571006865812752217367962054313612264 
action_result.data.\*.ssl_certificate.\*.subjectStreetAddress | string |  |   270 Brannan St, 
action_result.data.\*.ssl_certificate.\*.issuerOrganizationName | string |  |   Let's Encrypt 
action_result.data.\*.ssl_certificate.\*.subjectOrganizationName | string |  |   luxavate.com 
action_result.data.\*.ssl_certificate.\*.issuerStateOrProvinceName | string |  |   Texas 
action_result.data.\*.ssl_certificate.\*.issuerOrganizationUnitName | string |  |   News 
action_result.data.\*.ssl_certificate.\*.subjectStateOrProvinceName | string |  |   Texas 
action_result.data.\*.ssl_certificate.\*.subjectOrganizationUnitName | string |  |   News 
action_result.data.\*.ssl_certificates.\*.sha1 | string |  `sha1`  |   1c51e98fb3342365ca29bfe78d7533b7aa9f1b2d 
action_result.data.\*.ssl_certificates.\*.lastSeen | string |  |   2018-09-01 
action_result.data.\*.ssl_certificates.\*.firstSeen | string |  |   2018-08-01 
action_result.data.\*.ssl_certificates.\*.ipAddresses.\* | string |  `ip`  `passivetotal ipv6`  |   8.8.8.8 
action_result.status | string |  |   success  failed 
action_result.message | string |  |   Total records: 10 
action_result.summary.total_records | numeric |  |   10 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

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
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.query | string |  |   country 
action_result.parameter.field | string |  |   issuerCountry 
action_result.data.\*.ssl_certificates.\*.firstSeen | numeric |  |   1450684800000 
action_result.data.\*.ssl_certificates.\*.lastSeen | numeric |  |   1450684800000 
action_result.data.\*.ssl_certificates.\*.sha1 | string |  `sha1`  |   240461b20dbb24a61b0a986821c2ad01bd3a8522 
action_result.data.\*.ssl_certificates.\*.issueDate | string |  |   2020-02-15 
action_result.data.\*.ssl_certificates.\*.fingerprint | string |  |   f2:28:ea:c5:3f:8e:45:4f:32:d2:a6:12:73:18:9f:d1:92:32:8f:c9 
action_result.data.\*.ssl_certificates.\*.serialNumber | string |  |   8571006865812752217367962054313612264 
action_result.data.\*.ssl_certificates.\*.issuerCountry | string |  |   US 
action_result.data.\*.ssl_certificates.\*.issuerSurname | string |  |   Surname 
action_result.data.\*.ssl_certificates.\*.expirationDate | string |  |   Jan 09 17:59:21 2035 GMT 
action_result.data.\*.ssl_certificates.\*.issuerProvince | string |  |   Texas 
action_result.data.\*.ssl_certificates.\*.subjectCountry | string |  |   US 
action_result.data.\*.ssl_certificates.\*.subjectSurname | string |  |   Surname 
action_result.data.\*.ssl_certificates.\*.subjectAlternativeNames.\* | string |  |  
action_result.data.\*.ssl_certificates.\*.issuerGivenName | string |  |   Xpress 
action_result.data.\*.ssl_certificates.\*.subjectProvince | string |  |   Texas 
action_result.data.\*.ssl_certificates.\*.issuerCommonName | string |  |   Let's Encrypt Authority X3 
action_result.data.\*.ssl_certificates.\*.subjectGivenName | string |  |   luxavate.com 
action_result.data.\*.ssl_certificates.\*.subjectCommonName | string |  |   luxavate.com 
action_result.data.\*.ssl_certificates.\*.issuerEmailAddress | string |  |   abc@gmail.com 
action_result.data.\*.ssl_certificates.\*.issuerLocalityName | string |  |   Issuer Locality 
action_result.data.\*.ssl_certificates.\*.issuerSerialNumber | string |  |   8571006865812752217367962054313612264 
action_result.data.\*.ssl_certificates.\*.issuerStreetAddress | string |  |   270 Brannan St, 
action_result.data.\*.ssl_certificates.\*.subjectEmailAddress | string |  |   abc@gmail.com 
action_result.data.\*.ssl_certificates.\*.subjectLocalityName | string |  |   Subject Locality 
action_result.data.\*.ssl_certificates.\*.subjectSerialNumber | string |  |   8571006865812752217367962054313612264 
action_result.data.\*.ssl_certificates.\*.subjectStreetAddress | string |  |   270 Brannan St, 
action_result.data.\*.ssl_certificates.\*.issuerOrganizationName | string |  |   Let's Encrypt 
action_result.data.\*.ssl_certificates.\*.subjectOrganizationName | string |  |   luxavate.com 
action_result.data.\*.ssl_certificates.\*.issuerStateOrProvinceName | string |  |   Texas 
action_result.data.\*.ssl_certificates.\*.issuerOrganizationUnitName | string |  |   News 
action_result.data.\*.ssl_certificates.\*.subjectStateOrProvinceName | string |  |   Texas 
action_result.data.\*.ssl_certificates.\*.subjectOrganizationUnitName | string |  |   News 
action_result.data.\*.ssl_certificates.\*.sslVersion | string |  |   3 
action_result.status | string |  |   success  failed 
action_result.message | string |  |   Total Records: 10 
action_result.summary.total_records | numeric |  |   10 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get host components'
Retrieves the host attribute components of a query

Type: **investigate**  
Read only: **True**

<p>By default, 2000 records will be fetched per page. If more data exists, then use the 'page' parameter for pagination.</p>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | The domain or IP being queried | string | 
**from** |  optional  | The start date for Passive data (YYYY-MM-DD) | string | 
**to** |  optional  | The end date for Passive data (YYYY-MM-DD) | string | 
**page** |  optional  | Page number for paging through results, defaults to 0 | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.query | string |  |   abc.com 
action_result.parameter.from | string |  |   2018-09-01 
action_result.parameter.to | string |  |   2018-10-01 
action_result.parameter.page | numeric |  |   1 
action_result.data.\*.components.\*.label | string |  |   CloudFlare 
action_result.data.\*.components.\*.version | string |  |   1.7.0 
action_result.data.\*.components.\*.category | string |  |   CDN 
action_result.data.\*.components.\*.hostname | string |  |   www.abc.com 
action_result.data.\*.components.\*.address | string |  |   0.0.0.0 
action_result.data.\*.components.\*.lastSeen | string |  |   2018-09-01 07:09:57 
action_result.data.\*.components.\*.firstSeen | string |  |   2018-08-01 07:09:57 
action_result.status | string |  |   success  failed 
action_result.message | string |  |   Total Records: 10 
action_result.summary.total_records | numeric |  |   10 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get host pairs'
Retrieves the host attribute pairs related to the query

Type: **investigate**  
Read only: **True**

<p>By default, 2000 records will be fetched per page. If more data exists, then use the 'page' parameter for pagination.</p>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | The domain or IP being queried | string | 
**direction** |  required  | The directionality of the search | string | 
**from** |  optional  | The start date for Passive data (YYYY-MM-DD) | string | 
**to** |  optional  | The end date for Passive data (YYYY-MM-DD) | string | 
**page** |  optional  | Page number for paging through results, defaults to 0 | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.query | string |  |   abc.com 
action_result.parameter.direction | string |  |   parents  children 
action_result.parameter.from | string |  |   2020-01-13 
action_result.parameter.to | string |  |   2020-02-13 
action_result.parameter.page | numeric |  |   1 
action_result.data.\*.pairs.\*.cause | string |  |   topLevelRedirect 
action_result.data.\*.pairs.\*.child | string |  |   www.seagateshare.com 
action_result.data.\*.pairs.\*.parent | string |  |   86.152.19.0 
action_result.data.\*.pairs.\*.lastSeen | string |  |   2018-09-01 07:09:57 
action_result.data.\*.pairs.\*.firstSeen | string |  |   2018-08-01 05:03:16 
action_result.status | string |  |   success  failed 
action_result.message | string |  |   Total Records: 10 
action_result.summary.total_records | numeric |  |   10 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 