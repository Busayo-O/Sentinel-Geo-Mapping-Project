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
	                           
- Microsoft Sentinel	Security for monitoring and threat detection.
- Microsoft Azure for Cloud environment.
- Log Analytics Workspace	for Security log collection and analysis.
- KQL for Querying and analyzing network traffic.
- Threat Intel Indicators	for Threat intelligence information.
- NTA Net Analytics	for Network traffic analysis.
- IP Geolocation for identifying geographical locations.
- Azure Monitor Workbooks for data visualization and reporting Environments Used. </h2>

<h2>Program walk-through:</h2>

<p align="center">
Launch the utility: <br/>
<img src="https://i.imgur.com/62TgaWL.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
Select the disk:  <br/>
<img src="https://i.imgur.com/tcTyMUE.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
Enter the number of passes: <br/>
<img src="https://i.imgur.com/nCIbXbg.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
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
