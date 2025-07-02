<div align="center">
  <img src="https://github.com/user-attachments/assets/523985a4-07ce-4084-a36c-52a2243e502e" width="99%" alt="Boss of the SOC"/>
</div>

<h1> Splunk | Ransomware </h1>
Hector M. Reyes  | SOC Analysis | Boss of the SOC  </b>

[Google Docs Link | Splunk: Ransomware](https://docs.google.com/document/d/19y3aXtqZZPFv6Lv4ywes7nDzFUVKh1VeDm2lGbytTkc/pub)

<div align="center">
  <img src="https://github.com/user-attachments/assets/aa505c5a-cad1-49ef-96b1-62fa6f2c2272" width="40%" alt="Splunk Image"/>
</div>

## Intro to the Ransomware
After the excitement of yesterday, Alice has started to settle into her new job. Sadly, she realizes her new colleagues may not be the crack cybersecurity team she was led to believe before joining. Looking through her incident ticketing queue, she noticed that a “critical” ticket had never been addressed. Shaking her head, she begins to investigate. Apparently, on August 24th, Bob Smith, using a Windows 10 workstation named we8105desk, returned to his desk after working out and found his speakers blaring (click below to listen), his desktop image had changed (see below), and his files were inaccessible. Alice has seen this before... ransomware. After a quick conversation with Bob, Alice determines that Bob found a USB drive in the parking lot earlier in the day, plugged it into his desktop, and opened up a Word document on the USB drive called "Miranda_Tate_unveiled.dotm". With a resigned sigh, she begins to dig in. 

### Tools Used
> - Splunk | SIEM (Security Information and Event Management)
> - Windows Sandbox | Sandboxie-Plus
> - VirusTotal | AlientVault 
> - md5decrypt | REX Expressions

<div align="center">
  <img src="https://github.com/user-attachments/assets/721cf2af-5f8a-43c3-99ef-7bf1833c4111" width="50%" alt="sp1"/>
</div>

---

<img src="https://github.com/user-attachments/assets/2113c750-4fb1-43b6-9eb8-810a7b13638f" width="60%" alt="spg1"/>

## Pre-Engagement 
We have two pieces of evidence that we need to examine before we begin our analysis of the environment. First, we have the screen. The URL where the attackers posted their ransomware note, "Ransomware screenshot." Second, we have the voice memo, "Ransomware warning". The memo seems to have been intended to scare the victim, hoping they would make a rash decision and possibly make a mistake by opening these URLs and extracting the content to look for evidence. 
To do this, we will deploy a sandboxed environment. It's perilous to open URLs from malicious links. Since we're using Windows Sandbox, we can safely visit both URLs. We can inspect the web-facing application and use the information to get some clues. We can then extract both the images and the voice memo. The Sandbox environment allows us to open the properties of the files. We can use this data later when you analyze the Network Traffic in Splunk. <br /> 
Ransomware Screenshot: 
> https://botscontent.netlify.app/v1/cerber-sshot.png  (Picture 1.1-1.2)

Picture 1.1 <br/>
<img src="https://github.com/user-attachments/assets/9170860e-4d87-461a-ac46-2de721545ddd" width="40%" alt="Splunk - Ransomware - Pictures 1.1"/>

Picture 1.2 <br/>
<img src="https://github.com/user-attachments/assets/246caec0-34e4-4ee1-839b-20e918704e4c" width="30%" alt="Splunk - Ransomware - Pictures 1.2"/>

> Ransomware warning:
https://botscontent.netlify.app/v1/cerber-sample-voice.mp3  (Picture 1.3)

Picture 1.3 <br/>
<img src="https://github.com/user-attachments/assets/029dcabb-18e4-4c7e-913d-ed1bfa51b203" width="30%" alt="Picture 1.3"/>

---

## Ransomware 200: (Pictures 1.4 – 1.7)
What was the most likely IPv4 address of we8105desk on 24AUG2016? <br /> 
We have the hostname we8105desk, and the attack date is August 24, 2016.
- We can create our query to begin our analysis. 
- Date and time change from All time to the date range given.
- From here, we can look at the source_ip field on the left.
- We see that 192.168.250.100 was active on that date.
- We can open the address and see that it belonged to we8105desk on that date, confirming our suspicion.
- Enter Search: index="botsv1" host=we8105desk
- Answer: 192.168.250.100

Picture 1.4 <br/>
<img src="https://github.com/user-attachments/assets/58c4723d-a081-4c90-b2b8-42535999a95e" width="40%" alt="Picture 1.4"/>

Picture 1.5 <br/>
<img src="https://github.com/user-attachments/assets/e3aeb61e-aa16-4d45-b38d-9dafa6e3f726" width="30%" alt="Picture 1.5"/>

Picture 1.6 <br/>
<img src="https://github.com/user-attachments/assets/1ed9a8f6-7d4b-4d1f-9216-7ec14ac32dcc" width="30%" alt="Picture 1.6"/>

Picture 1.7 <br/>
<img src="https://github.com/user-attachments/assets/ef14cc90-4473-466d-a9c3-57d2f426f978" width="40%" alt="Picture 1.7"/>


## Ransomware 201:  (Pictures 1.8) <br /> 
Amongst the Suricata signatures that detected the Cerber malware, which one alerted the fewest number of times? Submit ONLY the signature ID value as the answer. <br /> 
- First, we need to determine where the signature could be located. We can access the source by going to the Suricata event logs. 
- We are looking for the alert.signature_id.
- We can sort it by count since we know we're looking for the fewest occurrences.
- You could also sort the events by count to find them.
- Enter Search: index=botsv1 sourcetype=suricata cerber | stats count by alert.signature_id | sort - count 
- Answer: 2816763

Picture 1.8 <br/>
<img src="https://github.com/user-attachments/assets/a6540b60-2ca3-4528-a0be-ebd99b9d74af" width="30%" alt="Picture 1.8"/>


## Ransomware 202: (Pictures 1.9-2.1) 
What fully qualified domain name (FQDN) does the Cerber ransomware attempt to direct the user to during its encryption phase? <br /> 
Let's add a DNS filter to our query: "stream: DNS." 
- We can use your IP address from 200 as the source IP.
- Enter Search: index=botsv1 sourcetype=stream:DNS src_ip=192.168.250.100
- At this point, we see too many entries. We can start adding filters to the legitimate DNS requests. By using the "NOT query="
- We can add Queries to requests that could be for .local, .arpa, or standard websites. We see the IP addresses used, such as Microsoft's MSN. </b>
- You can use Google to compare & contrast requests you can add.
- We can add "| table dest_ip _time query" to show the FQDNs for easier reading.
- I saw a suspicious FQDN. I opened it and found our suspect.
- Now that we had what we were looking for, I opened the event and had the attacker's information, date, and event time. 
- I will save this Search and take a screenshot for future use.
- Enter Search: index=botsv1 sourcetype=stream:DNS src_ip=192.168.250.100 NOT query=*.local NOT query=*.arpa  NOT query=*.microsoft.com NOT query=*.msn.com NOT query=*.info query=*.*| table dest_ip _time query
- Answer: cerberhhyed5frqa.xmfir0.win

Picture 1.9 <br/>
<img src="https://github.com/user-attachments/assets/1e7ffad3-f69e-45b2-997f-b36ad8953d97" width="30%" alt="Picture 1.9"/>

Picture 2.0 <br/>
<img src="https://github.com/user-attachments/assets/c13ed977-cebe-436d-8ac8-543c3f3140ae" width="40%" alt="Picture 2.0"/>

Picture 2.1 <br/>
<img src="https://github.com/user-attachments/assets/835d9100-dd18-40c6-ab0b-40b8d9df0105" width="40%" alt="Picture 2.1"/>


## Ransomware 203: (Pictures 2.2-2.5)
What was the first suspicious domain visited by we8105desk on 24 August 2016? <br /> 
- We already have the FQDNs sorted by time in the query, and we now know the time of the attack.
We can follow the timeline in the query until we encounter the first suspicious domain.
- Since we suspect these FQDNs could be malicious, let's return to them. Our Sandbox Container.
- Here, we can head to the link to inspect the website. 
- Use a URL analyzer to look past the network traffic of the FQDN for future use.
- Answer: solidaritedeproximite.org

Picture 2.2 <br/>
<img src="https://github.com/user-attachments/assets/5c4d0a64-1a7a-45d0-aefb-84e3cf21f94d" width="50%" alt="Picture 2.2"/>

Picture 2.3 <br/>
<img src="https://github.com/user-attachments/assets/edf498da-0d8b-401c-a524-29259c54307d" width="50%" alt="Picture 2.3"/>

Picture 2.4 <br/>
<img src="https://github.com/user-attachments/assets/cf13a1cf-ca12-4734-86fc-a20082817b17" width="40%" alt="Picture 2.4"/>

Picture 2.5 <br/>
<img src="https://github.com/user-attachments/assets/a17e0683-bb94-42d8-b79d-07b21fa59485" width="30%" alt="Picture 2.5"/>


## Ransomware 204: (Pictures 2.6-2.9)
What is the name of the USB key inserted by Bob Smith? <br /> 
We can start by looking at we8105desk's WinRegistry and filtering for a USB.
- Enter Search: index=botsv1 sourcetype="winregistry" host=we8105desk * USB”
- There are too many possible events, so we return to the Splunk_Platform.
- Let's replace the "* USB" command with "friendlyname." This will tell Splunk to Search for a registry entry value specific to USB devices. (Link 1.1)
- It works! Now I have two results. If I had still gotten multiple pages or no results, we could have headed to (Link 1.2). 
- We can use these Registry entries to filter our way to our USB device.
- Now, we can go to the data_1 field and see "MIRANDA_PRI" as the only event.
- “https://lantern.splunk.com/Splunk_Platform/UCE/Security/Incident_Management/Investigating_a_ransomware_attack/Removable_devices_connected_to_a_machine” (Link 1.1) 
- “https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/usb-device-specific-registry-settings.” (Link 1.2) 
- Enter Search: index=botsv1 sourcetype="winregistry" host=we8105desk friendlyname
- Answer: MIRANDA_PRI

Picture 2.6 <br/>
<img src="https://github.com/user-attachments/assets/4340cc89-034d-406b-9134-828d875446c7" width="30%" alt="Picture 2.6"/>

Picture 2.7 <br/>
<img src="https://github.com/user-attachments/assets/dddd2c71-a118-4016-8217-9b567fba321b" width="40%" alt="Picture 2.7"/>

Picture 2.8 <br/>
<img src="https://github.com/user-attachments/assets/0e6a944a-bd54-461d-bec7-4fd9332088b2" width="50%" alt="Picture 2.8"/>

Picture 2.9 <br/>
<img src="https://github.com/user-attachments/assets/425fdfd7-e272-4795-8dec-c7f57d6b044f" width="50%" alt="Picture 2.9"/>


## Ransomware 206: (Pictures 3.0) 
Bob Smith's workstation (we8105desk) was connected to a file server during the ransomware outbreak. What is the IPv4 address of the file server? <br /> 
- We can stay in the same query since we were looking at the Windows registry of the host we8105desk. 
- We replace the "friendlyname" name filter with "fileshare".
- We can see host = we8105desk is connecting to #192.168.250.20#fileshare
- Enter Search: index=botsv1 sourcetype="winregistry" host=we8105desk fileshare
- Answer: 192.168.250.20

Picture 3.0 <br/>
<img src="https://github.com/user-attachments/assets/93490f93-0c23-43de-adaf-dde888ff0d59" width="50%" alt="Picture 3.0"/>


## Ransomware 207: (Pictures 3.1-3.2) 
How many distinct PDFs did the ransomware encrypt on the remote file server? <br /> 
We can find the file server's name on the same line where we saw its IP.
- DestinationHostname = we9041srv
- We use it as a host and filter using the command *pdf. We saw 526 events.
- index=botsv1 host=we9041srv *.pdf
- We look at the distant value to count which file could have been encrypted in this list. We can use "dc" and "stat" and filter it using "Relative_Target_Name" in our command.
-  | stats dc(Relative_Target_Name)
- Enter Search: index=botsv1 host=we9041srv *.pdf | stats dc(Relative_Target_Name)
- Answer: we9041srv

Picture 3.1 <br/>
<img src="https://github.com/user-attachments/assets/a9a5ad65-596d-4b26-a639-ccc70904113b" width="50%" alt="Picture 3.1"/>

Picture 3.2 <br/>
<img src="https://github.com/user-attachments/assets/c8adc787-496c-4d0e-b8bf-518a12e7ee6e" width="40%" alt="Picture 3.2"/>


## Ransomware 208: (Pictures 3.3)  
The VBScript found in question 204 launches 121214.tmp. What is the ParentProcessId of this initial launch? (Pictures 1.1 – 1.4) <br /> 
Since we know the file name, we can return to the query we saved from step 204.
- Filter the scripts by adding the file name and looking at the parent_process_id field.
- Enter Search:  index=botsv1 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" *.vbs 121214.tmp
- Answer: 3968

Picture 3.3 <br/>
<img src="https://github.com/user-attachments/assets/ad3c9595-bfe2-472c-98a3-1c9bb6f5d3c0" width="30%" alt="Picture 3.3"/>


## Ransomware 209: (Pictures 3.4) 
The Cerber ransomware encrypts files located in Bob Smith's Windows profile. How many .txt files does it encrypt? <br /> 
- We can return to our earlier query, where we have Bob's hostname and directory.
- We can add ".txt" to his directory and use the "stats dc" command to improve our results.
- If you want his directory location for the search, click on his directory.
- Enter Search: index="botsv1" host=we8105desk sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" TargetFilename="C:\\Users\\bob.smith.WAYNECORPINC\\*.txt" | stats dc(TargetFilename)
- Answer: 406

Picture 3.4 <br/>
<img src="https://github.com/user-attachments/assets/457b12dc-67f9-4cdd-baec-20592d907094" width="50%" alt="Picture 3.4"/>


## Ransomware 210: (Pictures 3.5-3.6) 
The malware downloads a file that contains the Cerber ransomware cryptor code. What is the name of that file? <br /> 
- To get the file name, we head back to Suricata and inspect the network packets. 
- We can look at the raw text of the suspicious domain we found earlier. We found a .jpg.
- Enter Search: index=botsv1 sourcetype=suricata dest_ip="192.168.250.100"  "http.hostname"="solidaritedeproximite.org"
- Answer: mhtr.jpg

Picture 3.5 <br/>
<img src="https://github.com/user-attachments/assets/99ea1310-ba89-40fa-a9e1-94ece3814761" width="40%" alt="Picture 3.5"/>

Picture 3.6 <br/>
<img src="https://github.com/user-attachments/assets/150a20dd-7ae2-431e-a4f6-b67596ac26a7" width="50%" alt="Picture 3.6"/>


## Ransomware 211: (Pictures 3.7)
Now that you know the name of the ransomware's encryptor file, what obfuscation technique is it likely to use? <br /> 
- From here, we grab the field hash. We can use an analyzer like Virustotal.com.
- This type of technique is commonly used. 
- A quick search can reveal how this kind of file has been decoded in the past. We just needed the URL.
- Answer: Steganography

Picture 3.7 <br/>
<img src="https://github.com/user-attachments/assets/be99b708-c5fe-4929-8343-09d6c03a9c6d" width="50%" alt="Picture 3.7"/>

---

<img src="https://github.com/user-attachments/assets/da0a82ab-1698-4051-bc22-1460114541c9" width="50%" alt="Graph 11"/>


## Conclusion
This project demonstrates how Splunk can be utilized to detect and investigate ransomware attacks. By analyzing event logs from a simulated incident, we identified key indicators of compromise, such as unauthorized file encryption activity, suspicious PowerShell commands, and abnormal system behavior associated with ransomware execution.

This practical scenario explored how Splunk supports proactive threat detection and incident response. The project highlights essential skills for a Security Analyst, including log analysis, threat investigation, and SIEM tools to mitigate cyber risks—critical capabilities for protecting modern IT environments.

<img src="https://github.com/user-attachments/assets/1370fda4-5387-45b7-8efd-243db80a7ec2" width="60%" alt="Graph Conclusion"/>



