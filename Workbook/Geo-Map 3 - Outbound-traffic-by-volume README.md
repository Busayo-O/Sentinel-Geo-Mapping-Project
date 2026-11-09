<h1>Outbound Traffic by Volume - Exfiltration Detection</h1>

<h2>Description</h2>
This project analyzes outbound network traffic by volume to identify how much data is being sent to external IP addresses, measured in Megabytes, gigabytes, and terabytes. By Using Microsoft Sentinel, Azure Log Analytics, KQL, and Azure Monitor Workbooks, the project analyzes network traffic volume, identified external destination IP addresses, and visualized outbound traffic geographically. It gave visibility into where data is going.
<br />

<h2> Objectives </h2>

- Monitor outbound network traffic.
- Identify external IP addresses receiving large amounts of data.
- Calculate outbound data transfers in MB, GB, and TB.
- Identify countries and cities associated with public destination IPs.
- Highlight unusual traffic patterns for further investigation.
- Build a geographic visualization dashboard.

<h2>Tools and Technologies</h2>

- Microsoft Sentinel for Security Monitoring
- Azure log Analytics for Network log Analysis
- KQL for Querying and analyzing network traffic
- Azure Monitor Workbook for Data visualization
- NTANetAnalytics for Network traffic analytics

<h2>Program walk-through:</h2>
KQL QUERY:

```kql
NTANetAnalytics
| where TimeGenerated {TimeRange}
| where SubType == "FlowLog"
| where isnotempty(DestPublicIps)
| extend Parts = split(DestPublicIps, "|")
| where array_length(Parts) >= 7
| extend PublicIp = tostring(Parts[0]),
         AllowedFlows = tolong(Parts[3]),
         DeniedFlows = tolong(Parts[4]),
         BytesIn = tolong(Parts[5]),
         BytesOut = tolong(Parts[6])
| where isnotempty(PublicIp)
| where BytesOut > 0
| extend geo = geo_info_from_ip_address(PublicIp)
| extend Latitude = toreal(geo.latitude),
         Longitude = toreal(geo.longitude),
         Country = tostring(geo.country),
         City = tostring(geo.city)
| where isnotempty(City) and isnotempty(Country)
| where isnotempty(Latitude) and isnotempty(Longitude)
| summarize TotalBytesOut = sum(BytesOut),
            TotalBytesIn = sum(BytesIn),
            Sources = dcount(SrcIp),
            Ports = make_set(DestPort, 15) by PublicIp, Country, City, Latitude, Longitude
```

kql-query.png

Screenshot showing your KQL query
<img src="https://i.imgur.com/hJuTrrX.png" height="80%" width="80%"/>

<br />
<br />
geographic-traffic-map.png

Screenshot using JSON file showing the geographic distribution of outbound connections.:  <br/>
<img src="https://i.imgur.com/QzAC50a.png" height="80%" width="80%"/>

Screenshot showing a larger circle, indicating the data sent to the specific location geographic distribution of outbound connections with areas with large MB .:  <br/>
<img src="https://i.imgur.com/PulP0AG.png" height="80%" width="80%"/>

Screen shot showing that dAta was sent to the United States
<img src="https://i.imgur.com/52MBTe2.png" height="80%" width="80%"/>


<br> KQL Analysis performed the following activities:
-  Filtered network flow records by time range.
-  Extract public destination IP addresses.
-  Calculated outbound and inbound traffic volume.
-  Enrich public IP addresses with geographic information.
-  Group traffic by destination IP, country, and city.
-  Identify destinations with high outbound traffic volume.

<br /> Security Value
Large outbound traffic volumes can be an indicator of unusual data transfers.

This analysis was used to investigate:
- Unexpected external connections.
- Unusual data transfer patterns.
- Suspicious destination IP addresses.
- Potential data exfiltration activity.
  
<br /> Output
- A geographic map displaying external destination IP addresses and their locations.
- A list of public IP addresses receiving outbound network traffic ranked by the amount of outbound traffic received.
- Outbound data transfer volumes measured in MB, GB, or TB.
- The results helped to identify the external destinations receiving the largest volume of data from the network.
- Some external IP addresses receive significantly more outbound traffic than others.
- some destinations receive traffic through unexpected ports.
- Each bubble represents an external destination. Larger bubbles indicate higher outbound traffic volume

These observations helps to identify potentially suspicious data-transfer patterns.

<br> Conclusion
- This project demonstrated how KQL and Azure Monitor Workbooks can be used to monitor and analyze outbound network traffic.
- By querying the NTANetAnalytics table, I was able to develop an approach for identifying external destination IP addresses, measuring outbound traffic volume, and visualizing destination locations using IP geolocation.
- The analysis helped in recognizing unusual outbound traffic patterns, identify high-volume external destinations, and prioritize activities that may require further investigation.
- It also helped to demonstrate the importance of network traffic monitoring in identifying potential data exfiltration risks.
- High outbound traffic volume is not automatically evidence of data theft. It is an indicator that requires further investigation, including checking the destination, source device, user activity, application, and business purpose.


