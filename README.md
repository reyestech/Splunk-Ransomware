# Splunk.Bots

<img src="https://i.imgur.com/WaIk6nd.png" height="80%" width="80%" alt="Disk Sanitization Steps"/> 

<h1>Hector M. Reyes  | SOC Analysis </h1> | Boss of the SOC 2024 </h1>

 ### [Google Docs Link | Splunk: Ransomware](https://docs.google.com/document/d/19y3aXtqZZPFv6Lv4ywes7nDzFUVKh1VeDm2lGbytTkc/pub)


<h1> Splunk | Ransomware </h1>

![Betterpreview3](https://github.com/reyestech/Splunk-Ransomware/assets/153461962/1e47ca50-99c8-4c86-8d2b-ac54bb6eb381)

</b> </b>

<h2> Ransomware </h2>
After the excitement of yesterday, Alice has started to settle into her new job. Sadly, she realizes her new colleagues may not be the crack cybersecurity team she was led to believe before joining. Looking through her incident ticketing queue, she noticed that a “critical” ticket had never been addressed. Shaking her head, she begins to investigate. Apparently, on August 24th, Bob Smith, using a Windows 10 workstation named we8105desk, returned to his desk after working out and found his speakers blaring (click below to listen), his desktop image had changed (see below), and his files were inaccessible. Alice has seen this before... ransomware. After a quick conversation with Bob, Alice determines that Bob found a USB drive in the parking lot earlier in the day, plugged it into his desktop, and opened up a Word document on the USB drive called "Miranda_Tate_unveiled.dotm". With a resigned sigh, she begins to dig in.

 ### [Alternative Link | Google Docs | Splunk | Ransomware](https://docs.google.com/document/d/e/2PACX-1vRonE9OQYFepOAGVK52PCcDdhpSIkfdVq5BI1hp7zVNXQ0YRnbsj6lrpyR3tTTK233x8zg62E4MsE6a/pub)
 
<img src="https://i.imgur.com/5uOU9N1.png" height="80%" width="80%" alt="Disk Sanitization Steps"/> 

<h2>Tools Used</h2>

- <b> Splunk | SIEM (Security Information and Event Management) </b> 
- <b> Windows Sandbox | Sandboxie-Plus </b>
- <b> VirusTotal | AlientVault </b>
- <b> md5decrypt | REX Expressions </b>

<img src="https://i.imgur.com/VtSXpfm.png" height="80%" width="80%" alt="Disk Sanitization Steps"/> 

<h2>Pre-Engagement: </h2>
We have two pieces of evidence that we need to examine before we begin our analysis of the environment. First, we have the screen. The URL where the attackers posted their ransomware note, "Ransomware screenshot." Second, we have the voice memo, "Ransomware warning". The memo seems to have been intended to scare the victim, hoping they would make a rash decision and possibly make a mistake by opening these URLs and extracting the content to look for evidence. 
To do this, we will deploy a sandboxed environment. It's perilous to open URLs from malicious links. Since we're using Windows Sandbox, we can safely visit both URLs. We can inspect the web-facing application and use the information to get some clues. We can then extract both the images and the voice memo. The Sandbox environment allows us to open the properties of the files. We can use this data later when you analyze the Network Traffic in Splunk. <br /> 
Ransomware Screenshot: 
https://botscontent.netlify.app/v1/cerber-sshot.png  (Picture 1.1-1.2)
<br/><br/> 

Picture 1.1  <br /> 
<img src="https://i.imgur.com/63HM8LD.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Picture 1.2  <br /> 
<img src="https://i.imgur.com/U8wgtfW.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Ransomware warning:  <br /> 
https://botscontent.netlify.app/v1/cerber-sample-voice.mp3  (Picture 1.3)

Picture 1.3 <br /> 
<img src="https://i.imgur.com/lQcq4Jg.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br /><br /> 

Ransomware 200: (Pictures 1.4 – 1.7) <br /> 
What was the most likely IPv4 address of we8105desk on 24AUG2016? <br /> 
We have the hostname we8105desk, and the attack date is August 24, 2016.
- <b> We can create our query to begin our analysis. 
- <b> Date and time change from All time to the date range given.
- <b> From here, we can look at the source_ip field on the left.
- <b> We see that 192.168.250.100 was active on that date.
- We can open the address and see that it belonged to we8105desk on that date, confirming our suspicion.
- <b> Enter Search: index="botsv1" host=we8105desk
- <b> Answer: 192.168.250.100

Pictures 1.4 <br /> 
<img src="https://i.imgur.com/jhkWtOk.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Picture 1.5 <br /> 
<img src="https://i.imgur.com/SgRIKDd.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Pictures 1.6 <br /> 
<img src="https://i.imgur.com/oDo4p3p.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Pictures 1.7 <br /> 
<img src="https://i.imgur.com/mko7Ztb.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br /><br /> 

Ransomware 201:  (Pictures 1.8) <br /> 
Amongst the Suricata signatures that detected the Cerber malware, which one alerted the fewest number of times? Submit ONLY the signature ID value as the answer. <br /> 
- <b> First, we need to determine where the signature could be located. We can access the source by going to the Suricata event logs. 
- <b> We are looking for the alert.signature_id.
- We can sort it by count since we know we're looking for the fewest occurrences.
- <b> You could also sort the events by count to find them.
- <b> Enter Search: index=botsv1 sourcetype=suricata cerber | stats count by alert.signature_id | sort - count 
- <b> Answer: 2816763

Pictures 1.8 <br /> 
<img src="https://i.imgur.com/n84XtbJ.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
</b> </b>

Ransomware 202: (Pictures 1.9-2.1) <br /> 
What fully qualified domain name (FQDN) does the Cerber ransomware attempt to direct the user to during its encryption phase? <br /> 
Let's add a DNS filter to our query: "stream: DNS." 
- <b> We can use your IP address from 200 as the source IP.
- <b> Enter Search: index=botsv1 sourcetype=stream:DNS src_ip=192.168.250.100
- <b> At this point, we see too many entries. We can start adding filters to the legitimate DNS requests. By using the "NOT query="
- <b>We can add Queries to requests that could be for .local, .arpa, or standard websites. We see the IP addresses used, such as Microsoft's MSN. </b>
- <b> You can use Google to compare & contrast requests you can add.
- <b> We can add "| table dest_ip _time query" to show the FQDNs for easier reading.
- <b> I saw a suspicious FQDN. I opened it and found our suspect.
- <b> Now that we had what we were looking for, I opened the event and had the attacker's information, date, and event time. 
- <b> I will save this Search and take a screenshot for future use.
- <b> Enter Search: index=botsv1 sourcetype=stream:DNS src_ip=192.168.250.100 NOT query=*.local NOT query=*.arpa  NOT query=*.microsoft.com NOT query=*.msn.com NOT query=*.info query=*.*| table dest_ip _time query
- <b> Answer: cerberhhyed5frqa.xmfir0.win


Pictures 1.9 <br /> 
<img src="https://i.imgur.com/erNw6mo.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Pictures 2.0 <br /> 
<img src="https://i.imgur.com/SNBNdxZ.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 
Pictures 2.1 <br /> 
<img src="https://i.imgur.com/WMdezAR.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br /><br /> 
 
Ransomware 203: (Pictures 2.2-2.5)  <br /> 
What was the first suspicious domain visited by we8105desk on 24 August 2016? <br /> 
- <b> We already have the FQDNs sorted by time in the query, and we now know the time of the attack.
We can follow the timeline in the query until we encounter the first suspicious domain.
- <b> Since we suspect these FQDNs could be malicious, let's return to them. Our Sandbox Container.
- <b> Here, we can head to the link to inspect the website. 
- <b> Use a URL analyzer to look past the network traffic of the FQDN for future use.
- <b> Answer: solidaritedeproximite.org

Pictures 2.2 <br /> 
<img src="https://i.imgur.com/LtWiQqf.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Pictures 2.3 <br /> 
<img src="https://i.imgur.com/RbNZavr.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Pictures 2.4  <br /> 
<img src="https://i.imgur.com/SVmOXlo.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Pictures 2.5 <br /> 
<img src="https://i.imgur.com/pxOEoUX.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br /><br /> 

Ransomware 204: (Pictures 2.6-2.9)  <br /> 
What is the name of the USB key inserted by Bob Smith? <br /> 
We can start by looking at we8105desk's WinRegistry and filtering for a USB.
- <b> Enter Search: index=botsv1 sourcetype="winregistry" host=we8105desk * USB”
- <b> There are too many possible events, so we return to the Splunk_Platform.
- <b> Let's replace the "* USB" command with "friendlyname." This will tell Splunk to Search for a registry entry value specific to USB devices. (Link 1.1)
- <b> It works! Now I have two results. If I had still gotten multiple pages or no results, we could have headed to (Link 1.2). 
- <b> We can use these Registry entries to filter our way to our USB device.
- <b> Now, we can go to the data_1 field and see "MIRANDA_PRI" as the only event.
- <b> “https://lantern.splunk.com/Splunk_Platform/UCE/Security/Incident_Management/Investigating_a_ransomware_attack/Removable_devices_connected_to_a_machine” (Link 1.1) 
- <b> “https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/usb-device-specific-registry-settings.” (Link 1.2) 
- <b> Enter Search: index=botsv1 sourcetype="winregistry" host=we8105desk friendlyname
- <b> Answer: MIRANDA_PRI

Pictures 2.6 <br /> 
<img src="https://i.imgur.com/7EKTsck.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Pictures 2.7 <br /> 
<img src="https://i.imgur.com/yHJL7bi.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Pictures 2.8  <br /> 
<img src="https://i.imgur.com/4ul6Eai.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Pictures 2.9 <br /> 
<img src="https://i.imgur.com/qBFlcVC.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br /><br /> 

Ransomware 206: (Pictures 3.0)  <br /> 
Bob Smith's workstation (we8105desk) was connected to a file server during the ransomware outbreak. What is the IPv4 address of the file server? <br /> 
- We can stay in the same query since we were looking at the Windows registry of the host we8105desk. 
We replace the "friendlyname" name filter with "fileshare".
- <b> We can see host = we8105desk is connecting to #192.168.250.20#fileshare
- <b> Enter Search: index=botsv1 sourcetype="winregistry" host=we8105desk fileshare
- <b> Answer: 192.168.250.20

Pictures 3.0 <br /> 
<img src="https://i.imgur.com/vUgtCkZ.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
</b> </b>

Ransomware 207: (Pictures 3.1-3.2)  <br /> 
How many distinct PDFs did the ransomware encrypt on the remote file server? <br /> 
We can find the file server's name on the same line where we saw its IP.
- <b> DestinationHostname = we9041srv
- <b> We use it as a host and filter using the command *pdf. We saw 526 events.
- <b> index=botsv1 host=we9041srv *.pdf
- <b> We look at the distant value to count which file could have been encrypted in this list. We can use "dc" and "stat" and filter it using "Relative_Target_Name" in our command.
- <b> | stats dc(Relative_Target_Name)
- <b> Enter Search: index=botsv1 host=we9041srv *.pdf | stats dc(Relative_Target_Name)
- <b> Answer: we9041srv

Pictures 3.1		<br />
<img src="https://i.imgur.com/lxjzzcz.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Pictures 3.2  <br /> 
<img src="https://i.imgur.com/96s697G.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br /><br /> 

Ransomware 208: (Pictures 3.3)  <br /> 
The VBScript found in question 204 launches 121214.tmp. What is the ParentProcessId of this initial launch? (Pictures 1.1 – 1.4) <br /> 
Since we know the file name, we can return to the query we saved from step 204.
- <b> Filter the scripts by adding the file name and looking at the parent_process_id field.
- <b> Enter Search:  index=botsv1 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" *.vbs 121214.tmp
- <b> Answer: 3968
</b> </b>

Pictures 3.3 <br /> 
<img src="https://i.imgur.com/L481gbJ.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br /><br /> 

Ransomware 209: (Pictures 3.4)  <br /> 
The Cerber ransomware encrypts files located in Bob Smith's Windows profile. How many .txt files does it encrypt? <br /> 
- <b> We can return to our earlier query, where we have Bob's hostname and directory.
- We can add ".txt" to his directory and use the "stats dc" command to improve our results.
- <b> If you want his directory location for the search, click on his directory.
- <b> Enter Search: index="botsv1" host=we8105desk sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" TargetFilename="C:\\Users\\bob.smith.WAYNECORPINC\\*.txt" | stats dc(TargetFilename)
- <b> Answer: 406

Pictures 3.4 <br /> 
<img src="https://i.imgur.com/0o7HjvF.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br /><br /> 

Ransomware 210: (Pictures 3.5-3.6)  <br /> 
The malware downloads a file that contains the Cerber ransomware cryptor code. What is the name of that file? <br /> 
- <b> To get the file name, we head back to Suricata and inspect the network packets. 
- <b> We can look at the raw text of the suspicious domain we found earlier. We found a .jpg.
- <b> Enter Search: index=botsv1 sourcetype=suricata dest_ip="192.168.250.100"  "http.hostname"="solidaritedeproximite.org"
- <b> Answer: mhtr.jpg

Pictures 3.5 <br /> 
<img src="https://i.imgur.com/eNs1kxr.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Pictures 3.6 <br /> 
<img src="https://i.imgur.com/yg2ioZe.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

<img src="https://i.imgur.com/Kz8EtRM.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br /><br /> 

Ransomware 211: (Pictures 3.7)  <br /> 
Now that you know the name of the ransomware's encryptor file, what obfuscation technique is it likely to use? <br /> 
- <b> From here, we grab the field hash. We can use an analyzer like Virustotal.com.
- <b> This type of technique is commonly used. 
- <b> A quick search can reveal how this kind of file has been decoded in the past. We just needed the URL.
- <b> Answer: Steganography
</b> </b>

Pictures 3.7 <br />
<img src="https://i.imgur.com/uY6ECOg.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

<img src="https://i.imgur.com/zVU2wPz.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>



