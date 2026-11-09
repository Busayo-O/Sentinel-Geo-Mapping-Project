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
// STEP 1: Built an active Threat Intelligence IP watchlist to create a list of currently malicious IP addresses 
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
NTANetAnalytics(showing the Network traffic like Source IP, destination IP)
| where SubType == "FlowLog"
| where AllowedInFlows > 0
| where isnotempty(SrcIp)

// STEP 3: Match network traffic against threat intelligence. It compares the source IP addresses in your network traffic logs against the malicious IP addresses in your threat intelligence list. An IP address appears in the results only when it matches both datasets. i.e joins two dissimilar tables where the IP addresses match (joining the NTANetAnalytics Table to the TI_IP's Output). It joins on the Source IP from the NTA Net Analytics table to the threat intelligence IP on the Threat intel Table. It joins from the threat intelligence table to the NTA Analytics table, where the IP addresses are the same. It compares the source IP addresses in your network traffic logs against the malicious IP addresses in your threat intelligence list.

An IP address appears in the results only when it matches both datasets.
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
	
## Screenshot showing malicious IP addresses	
  <img src="https://i.imgur.com/bgZ3VZG.png" width="80%" alt="Malicious IP addresses screenshot">
</p>

## Screenshot
  <img src="https://i.imgur.com/ZuJwwj4.png" width="80%" alt="Screenshot">
</p>
  
## Screenshot showing the two tables joined together
<img src="https://i.imgur.com/Cz0y43d.png" height="80%" width="80%" alt= "Screenshot"/>
</p>

## Screenshot showing the Json Workbook Map
<img src="https://i.imgur.com/cMpNb2P.png" height="80%" width="80%" alt="Screenshot"/>
</p>

The map is configured with:
Map feature         	Meaning
Bubble size        Allowed inbound flows
Bubble colour	   Intended to represent inbound data volume
Map location	   Latitude and longitude of the source IP
Map label	       IP address, city, country, allowed flows and targets


Output
The Microsoft Sentinel workbook produced two main visualizations:

A. A Geographical threat intelligence map
- Showing geographical locations of matched suspicious IP addresses.
- Identified external IPs associated with allowed inbound traffic.
- Displayed number of allowed flows.
- Shows the number of internal destinations reached.
- Geographical patterns were identified.
  
B. A Threat intelligence source breakdown table, which shows
- Source IP address.
- Country, state and city.
- Allowed flows.
- Denied flows.
- Data volume received.
- Destination ports.
- Threat confidence.
- Threat categories.

## Project conclusion
The project demonstrates how Microsoft Sentinel correlates threat intelligence indicators with actual network traffic to identify potentially malicious IP addresses that successfully communicated with cyber Range's internal environment.

By combining threat intelligence, network traffic analysis, geographical enrichment and traffic aggregation, suspicious connections were identified, investigate potentially exposed internal systems and prioritize threats based on their network activity.


