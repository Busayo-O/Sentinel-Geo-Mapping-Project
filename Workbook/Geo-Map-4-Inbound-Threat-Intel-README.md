<h1>Allowed Inbound Flows from Threat Intelligence IPs</h1>


<h2>Description</h2>
This project uses Microsoft Sentinel and Kusto Query Language (KQL) to identify potentially malicious external IP addresses that have successfully sent traffic into the Cyber Range network.

It combines two data sources:
- ThreatIntelIndicators: Identifies known malicious or suspicious IP addresses.
- NTANetAnalytics: Provides network traffic information, including allowed and denied inbound flows, entering and leaving the Cyber Range environment.
The project enriches suspicious IP addresses with geographical information and displays their locations on a Microsoft Sentinel workbook map.

The objective is to help security analysts identify suspicious inbound connections, determine which internal destinations were reached, and prioritize potentially dangerous network activity.

<br />

<h2>Objectives</h2>

- Identify active threat intelligence IP addresses.
- Detect inbound traffic originating from threat-intelligence-listed IPs.
- Identify connections that were allowed into the network.
- Determine the number of internal destinations reached.
- Identify destination ports associated with suspicious traffic.
- Enrich suspicious IP addresses with geographical information.
- Visualize suspicious inbound connections using a geographical map.
- Prioritize suspicious IP addresses for further investigation.</h2>

<h2>Technologies and Purpose</h2>
	                           
- Microsoft Sentinel Security for monitoring and threat detection.
- Microsoft Azure for Cloud environment.
- Log Analytics Workspace	for Security log collection and analysis.
- KQL for Querying and analyzing network traffic.
- Threat Intel Indicators	for Threat intelligence information.
- NTA Net Analytics	for Network traffic analysis.
- IP Geolocation for identifying geographical locations.
- Azure Monitor Workbooks for data visualization and reporting Environments Used. </h2>

<h2>KQL QUERY Implementation:</h2>

The query has five main activities:

- Threat intelligence collection.
- Network traffic filtering.
- Threat intelligence correlation.
- Geographical enrichment.
- Traffic aggregation and visualization

```kql Query
// STEP 1: Build an active Threat Intelligence IP watchlist
let TI_IPs =
    ThreatIntelIndicators
    | where TimeGenerated > ago(30d)
    | summarize arg_max(TimeGenerated, *) by Id
    | where IsActive == true
    | where isempty(ValidUntil) or ValidUntil > now()
    | where ObservableKey in (
        "ipv4-addr:value",
        "network-traffic:src_ref.value",
        "network-traffic:dst_ref.value"
    )
    | extend ThreatType = tostring(Data.indicator_types[0])
    | project TI_IP = ObservableValue,
              Confidence,
              ThreatType,
              Tags
    | where isnotempty(TI_IP);

// STEP 2: Retrieve allowed inbound network traffic
NTANetAnalytics
| where TimeGenerated {TimeRange}
| where SubType == "FlowLog"
| where AllowedInFlows > 0
| where isnotempty(SrcIp)

// STEP 3: Match network traffic against threat intelligence
| join kind=inner TI_IPs
    on $left.SrcIp == $right.TI_IP

// STEP 4: Enrich suspicious IPs with geographical information
| extend geo = geo_info_from_ip_address(SrcIp)
| extend Latitude = toreal(geo.latitude),
         Longitude = toreal(geo.longitude),
         Country = tostring(geo.country),
         State = tostring(geo.state),
         City = tostring(geo.city)

// STEP 5: Filter IPs with available geographical information
| where isnotempty(City) and isnotempty(Country)
| where isnotempty(Latitude) and isnotempty(Longitude)

// STEP 6: Aggregate suspicious inbound traffic
| summarize
    AllowedFlows = sum(AllowedInFlows),
    DeniedFlows = sum(DeniedInFlows),
    BytesIn = sum(BytesSrcToDest),
    Targets = dcount(DestIp),
    Ports = make_set(DestPort, 15),
    MaxConfidence = max(Confidence),
    ThreatTypes = make_set(ThreatType, 10)
    by SrcIp, Country, State, City, Latitude, Longitude

// STEP 7: Generate geographical map labels
| extend MapLabel = strcat(
    SrcIp,
    " (", City, ", ", State, ", ", Country,
    ") - ", AllowedFlows,
    " allowed, ", Targets, " targets"
)

// STEP 8: Display and rank investigation results
| project
    Latitude,
    Longitude,
    MapLabel,
    AllowedFlows,
    DeniedFlows,
    BytesIn,
    Targets,
    Ports,
    MaxConfidence,
    ThreatTypes,
    SrcIp,
    Country,
    State,
    City

| order by AllowedFlows desc, Targets desc
```
  
<p align="center">
<h2>Step 1: Built a Threat Intelligence IP list to create a list of currently malicious IP addresses </h2>
	
Explanation:
- Retrieves threat intelligence indicators from the last 30 days.
- Removes duplicate indicators using arg_max().
- Keeps only active indicators.
- Excludes expired indicators.
  
<h2> Step 2: Identify IP address types: This filters the threat intelligence feed to focus on IP address indicators </h2>
	
<h2> Step 3: Extract threat information


             
<br />
<img src="https://i.imgur.com/bgZ3VZG.png" height="80%" width="80%" alt="/>
https://i.imgur.com/bgZ3VZG.png
<br />
Confirm your selection:  <br/>
<img src="https://i.imgur.com/cdFHBiU.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
Wait for process to complete (may take some time):  <br/>
<img src="https://i.imgur.com/JL945Ga.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
Sanitization complete:  <br/>
<img src="https://i.imgur.com/K71yaM2.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
Observe the wiped disk:  <br/>
<img src="https://i.imgur.com/AeZkvFQ.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
</p>

<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>
