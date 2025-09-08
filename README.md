<div align="center">
  <img src="https://github.com/user-attachments/assets/523985a4-07ce-4084-a36c-52a2243e502e" width="95%" alt="Boss of the SOC"/>
</div>

---

# Splunk: Ransomware  
### Splunk IR Lab — Cerber Ransomware: Detect, Trace, Contain  
**Hector M. Reyes | Boss of the SOC** | `02 Feb 2024`

<div align="center">
  <img src="https://github.com/user-attachments/assets/39d8bb3d-2dc3-4579-a89c-526ecf50c487" width="50%" alt="Cerber Ransomware"/>
</div>

📝 TL;DR
- Confirmed Cerber ransomware on the host we8105desk using Splunk SIEM data.
- Traced infection path: USB lure → Word macro → VBScript payload → encryption → lateral spread.
- Captured IoCs (IPs, hashes, filenames, registry keys) and documented detection, containment, and hardening.

Key skills:
> Splunk SPL queries, timeline reconstruction, process lineage, registry analysis, DNS filtering, IOC extraction, and IR playbook design.

## **Scenario**

After the excitement of yesterday, Alice has started to settle into her new job. Sadly, she realizes her new colleagues may not be the crack cybersecurity team she was led to believe before joining. Looking through her incident ticketing queue, she noticed a “critical” ticket was never addressed. Shaking her head, she begins to investigate. Apparently, on August 24th, Bob Smith (using a Windows 10 workstation named we8105desk) came back to his desk after working out and found his speakers blaring (click below to listen), his desktop image changed (see below) and his files inaccessible. Alice has seen this before... ransomware. After a quick conversation with Bob, Alice determines that Bob found a USB drive in the parking lot earlier in the day, plugged it into his desktop, and opened up a Word document on the USB drive called "Miranda_Tate_unveiled.dotm". With a resigned sigh, she begins to dig in.

<div align="center">
  <img src="https://github.com/user-attachments/assets/721cf2af-5f8a-43c3-99ef-7bf1833c4111" width="45%" alt="Splunk Intro Evidence"/>
</div>

--- 

## **Intro to the Ransomware**
### Your Assignment (Objectives)
The main goal of this lab is to confirm ransomware activity, trace how it entered the environment, and document the attacker’s path. As the SOC analyst, you must identify the infected host, understand the infection vector, and collect supporting evidence for containment and remediation. By following each step, you will gain experience with Splunk queries, correlation, and building repeatable workflows for incident response.
- Confirm Cerber encryption activity on the host we8105desk.
- Trace the attack path: USB → macro → payload → encryption → lateral spread.
- Identify key IoCs: IPs, filenames, hashes, domains.
- Document detection, containment, and hardening steps.
- Practice repeatable detection engineering.

### Evidence Artifacts
The attackers left behind artifacts to intimidate the victim and provide breadcrumbs for the investigation. These serve as both starting points and pivot material in Splunk.
- **Ransom note screenshot** on the desktop: **Screenshot**: https://botscontent.netlify.app/v1/cerber-sshot.png `Picture 1.1-Picture 1.2`
- **Voice memo warning**, designed to panic the user: **Voice Memo**: https://botscontent.netlify.app/v1/cerber-sample-voice.mp `Picture 1.3`
- **USB-delivered Word file:** Miranda_Tate_unveiled.dotm
- **Desktop wallpaper change** (visual indicator of infection).

<div align="center">
  <img src="https://github.com/user-attachments/assets/9170860e-4d87-461a-ac46-2de721545ddd" width="30%" alt="Picture 1.1"/>
  <img src="https://github.com/user-attachments/assets/246caec0-34e4-4ee1-839b-20e918704e4c" width="30%" alt="Picture 1.2"/>
  <img src="https://github.com/user-attachments/assets/029dcabb-18e4-4c7e-913d-ed1bfa51b203" width="30%" alt="Picture 1.3"/>
</div>

<p align="center">
  <i>Picture 1.1 — Ransom note screenshot</i> &nbsp;&nbsp; | &nbsp;&nbsp; 
  <i>Picture 1.2 — Desktop wallpaper change</i> &nbsp;&nbsp; | &nbsp;&nbsp; 
  <i>Picture 1.3 — Audio warning memo</i>
</p>

--- 

## 🛠️ Hunt Setup & Pre-Engagement  
Before starting Splunk hunts, I staged my environment and outlined the necessary data sources for the investigation. This preparation ensured that the evidence could be safely reviewed, enriched, and then imported into Splunk for structured analysis.

**Prep Work (Safe Evidence Review):**  
- Used Windows Sandbox and Sandboxie-Plus to inspect the ransom screenshot and audio memo safely.
- Captured hashes, filenames, and metadata for enrichment using tools like VirusTotal and AlienVault OTX.
- Logged Indicators of Compromise (IoCs)—including IP addresses, Fully Qualified Domain Names (FQDNs), hashes, and filenames—into a scratchpad for later pivoting.

**Splunk Hunt Setup:**  
- **Time Window**: Aug 24, 2016 (00:00–23:59).  
- **Primary Host**: `we8105desk` (expected IP ≈ `192.168.250.100`).  
- **Key Data Sources**:  
  - `stream:DNS` → suspicious domains.  
  - `suricata` → payload delivery.  
  - `XmlWinEventLog:Sysmon` → process lineage + encryption activity.  
  - `winregistry` → USB artifacts + persistence checks.  
- **Reference Artifacts**: ransom screenshot, audio memo, and USB-delivered file.  

**Pro Tips:**  
- Always lock the **time picker** before pivoting queries.  
- Use the **fields sidebar** for quick pivots (`src_ip`, `fileinfo.filename`, `ParentProcessId`).  
- Save useful queries as **Reports** → convert to **Alerts** later.  
- Build a repeatable **IoC scratchpad** for rapid enrichment and correlation.  
> 🕵️‍♂️ Happy Hunting!

### 📦 Tools Reference
| Category     | Tool / Feature                     | Purpose                                                     |
| ------------ | ---------------------------------- | ----------------------------------------------------------- |
| SIEM         | Splunk                             | Search, detections, evidence timeline                       |
| Sandbox      | Windows Sandbox / Sandboxie-Plus   | Safe inspection of URLs/files                               |
| Threat Intel | VirusTotal / AlienVault OTX        | Hash/domain/IP enrichment                                   |
| Windows      | Sysmon + WinEvent / WinRegistry    | Process/file telemetry; device/USB artifacts                |
| Parsing      | REX / `stats` / `transaction`      | Extract fields; counts; durations                           |

---


## Ransomware 200 — Identify Patient-Zero (Host IPv4)
What was the most likely IPv4 address of we8105desk on 24AUG2016? <br /> 
We have the hostname we8105desk, and the attack date is August 24, 2016.
- We can create our query to begin our analysis. 
- Date and time change from All time to the date range given.
- From here, we can look at the source_ip field on the left.
- We see that 192.168.250.100 was active on that date.
- We can open the address and see that it belonged to we8105desk on that date, confirming our suspicion.
- Enter Search: index="botsv1" host=we8105desk

Inputs: `host=we8105desk`
Answer guidance: Enter an IPv4 address only, e.g., 192.168.1.10.
**SPL**
```
index=botsv1 host=we8105desk earliest=08/24/2016:00:00:00 latest=08/25/2016:00:00:00
| stats dc(src_ip) as srcs values(src_ip) as ips
```
Validate: Browse raw events; confirm src_ip in context.
- [ ] **Answer:** `192.168.250.100`

<img src="https://github.com/user-attachments/assets/58c4723d-a081-4c90-b2b8-42535999a95e" width="40%" alt="Picture 1.4"/>

`Picture 1.4`

<img src="https://github.com/user-attachments/assets/e3aeb61e-aa16-4d45-b38d-9dafa6e3f726" width="30%" alt="Picture 1.5"/>

`Picture 1.5`

<img src="https://github.com/user-attachments/assets/1ed9a8f6-7d4b-4d1f-9216-7ec14ac32dcc" width="30%" alt="Picture 1.6"/>

`Picture 1.6`

<img src="https://github.com/user-attachments/assets/ef14cc90-4473-466d-a9c3-57d2f426f978" width="40%" alt="Picture 1.7"/>

`Picture 1.7`

---

## Ransomware 201 — Suricata Signature With Fewest Alerts
Amongst the Suricata signatures that detected the Cerber malware, which one alerted the fewest number of times? Submit ONLY the signature ID value as the answer. <br /> 
- First, we need to determine where the signature could be located. We can access the source by going to the Suricata event logs. 
- We are looking for the alert.signature_id.
- We can sort it by count since we know we're looking for the fewest occurrences.
- You could also sort the events by count to find them.
- Enter Search: index=botsv1 sourcetype=suricata cerber | stats count by alert.signature_id | sort - count

Goal: Among Cerber Suricata signatures, find the least frequent signature ID.
Answer guidance: Enter the Suricata signature ID only, e.g., 2816763.
**SPL**
```
index=botsv1 sourcetype=suricata cerber earliest=08/24/2016:00:00:00 latest=08/25/2016:00:00:00
| stats count by alert.signature_id
| sort count
| head 1
```
Validate: Open sample events; confirm the ID context.
- [ ] **Answer:** `2816763`

<img src="https://github.com/user-attachments/assets/a6540b60-2ca3-4528-a0be-ebd99b9d74af" width="30%" alt="Picture 1.8"/>

`Picture 1.8`

---

## Ransomware 202 — FQDN Used During Encryption
What fully qualified domain name (FQDN) does the Cerber ransomware attempt to direct the user to during its encryption phase? <br /> 
- Let's add a DNS filter to our query: "stream: DNS." We can use your IP address from 200 as the source IP. Enter Search: index=botsv1 sourcetype=stream:DNS src_ip=192.168.250.100
- At this point, we see too many entries. We can start adding filters to the legitimate DNS requests. By using the "NOT query="
- We can add Queries to requests that could be for .local, .arpa, or standard websites. We see the IP addresses used, such as Microsoft's MSN. </b>
- You can use Google to compare & contrast requests you can add. - We can add "| table dest_ip _time query" to show the FQDNs for easier reading.
- I saw a suspicious FQDN. I opened it and found our suspect. Now that we had what we were looking for, I opened the event and had the attacker's information, date, and event time. I will save this Search and take a screenshot for future use.
- Enter Search: index=botsv1 sourcetype=stream:DNS src_ip=192.168.250.100 NOT query=*.local NOT query=*.arpa  NOT query=*.microsoft.com NOT query=*.msn.com NOT query=*.info query=*.*| table dest_ip _time query

Goal: Identify Cerber’s ransom site FQDN queried during encryption.
Inputs: src_ip=192.168.250.100, filter benign domains.
**SPL**
```
index=botsv1 sourcetype=stream:DNS src_ip=192.168.250.100 earliest=08/24/2016:00:00:00 latest=08/25/2016:00:00:00
| search NOT query=*.local NOT query=*.arpa NOT query=*.microsoft.com NOT query=*.msn.com NOT query=*.info
| table _time query dest_ip
| sort _time
```
Validate: Inspect around the encryption timeframe.
- [ ] **Answer:** `cerberhhyed5frqa.xmfir0.win`

<img src="https://github.com/user-attachments/assets/1e7ffad3-f69e-45b2-997f-b36ad8953d97" width="30%" alt="Picture 1.9"/>

`Picture 1.9`

<img src="https://github.com/user-attachments/assets/c13ed977-cebe-436d-8ac8-543c3f3140ae" width="40%" alt="Picture 2.0"/>

`Picture 2.0`

<img src="https://github.com/user-attachments/assets/835d9100-dd18-40c6-ab0b-40b8d9df0105" width="40%" alt="Picture 2.1"/>

`Picture 2.1`

---

## Ransomware 203 — First Suspicious Domain Visited
What was the first suspicious domain visited by we8105desk on 24 August 2016? <br /> 
- We already have the FQDNs sorted by time in the query, and we now know the time of the attack.
We can follow the timeline in the query until we encounter the first suspicious domain.
- Since we suspect these FQDNs could be malicious, let's return to them. Our Sandbox Container.
- Here, we can head to the link to inspect the website. 
- Use a URL analyzer to look past the network traffic of the FQDN for future use.

Goal: Find the earliest suspicious domain that day.
**SPL**
```
index=botsv1 sourcetype=stream:DNS src_ip=192.168.250.100 earliest=08/24/2016:00:00:00 latest=08/25/2016:00:00:00
| search NOT query=*.local NOT query=*.arpa NOT query=*.microsoft.com NOT query=*.msn.com
| table _time query
| sort 0 _time
| head 1
```
Validate: Sanity-check with sandbox/URL analyzer (don’t browse on prod).
- [ ] **Answer:** `solidaritedeproximite.org`

<img src="https://github.com/user-attachments/assets/5c4d0a64-1a7a-45d0-aefb-84e3cf21f94d" width="50%" alt="Picture 2.2"/>

`Picture 2.2`

<img src="https://github.com/user-attachments/assets/edf498da-0d8b-401c-a524-29259c54307d" width="50%" alt="Picture 2.3"/>

`Picture 2.3`

<img src="https://github.com/user-attachments/assets/cf13a1cf-ca12-4734-86fc-a20082817b17" width="40%" alt="Picture 2.4"/>

`Picture 2.4`

<img src="https://github.com/user-attachments/assets/a17e0683-bb94-42d8-b79d-07b21fa59485" width="30%" alt="Picture 2.5"/>

`Picture 2.5`

---

## Ransomware 204 — USB Key Name (WinRegistry)
What is the name of the USB key inserted by Bob Smith? <br /> 
We can start by looking at we8105desk's WinRegistry and filtering for a USB.
- Enter Search: index=botsv1 sourcetype="winregistry" host=we8105desk * USB”
- There are too many possible events, so we return to the Splunk_Platform.
- Let's replace the "* USB" command with "friendlyname." This will tell Splunk to Search for a registry entry value specific to USB devices. `Link 1.1`
- It works! Now I have two results. If I had still gotten multiple pages or no results, we could have headed to `Link 1.2`. 
- We can use these Registry entries to filter our way to our USB device.
- Now, we can go to the data_1 field and see "MIRANDA_PRI" as the only event.
- "https://lantern.splunk.com/Splunk_Platform/UCE/Security/Incident_Management/Investigating_a_ransomware_attack/Removable_devices_connected_to_a_machine"  `Link 1.1`
- "https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/usb-device-specific-registry-settings." `Link 1.2`. 
- Enter Search: index=botsv1 sourcetype="winregistry" host=we8105desk friendlyname

Goal: Identify the USB-friendly name Bob inserted.
Inputs: `host=we8105desk`, `sourcetype=winregistry`
**SPL**
```
index=botsv1 sourcetype=winregistry host=we8105desk earliest=08/24/2016:00:00:00 latest=08/25/2016:00:00:00 friendlyname
| table _time host friendlyname data_* registry_path
| sort _time
```
Validate: Confirm the friendly name appears near initial access.
- [ ] **Answer:** `MIRANDA_PRI`

<img src="https://github.com/user-attachments/assets/4340cc89-034d-406b-9134-828d875446c7" width="30%" alt="Picture 2.6"/>

`Picture 2.6`

<img src="https://github.com/user-attachments/assets/dddd2c71-a118-4016-8217-9b567fba321b" width="40%" alt="Picture 2.7"/>

`Picture 2.7`

<img src="https://github.com/user-attachments/assets/0e6a944a-bd54-461d-bec7-4fd9332088b2" width="50%" alt="Picture 2.8"/>

`Picture 2.8`

<img src="https://github.com/user-attachments/assets/425fdfd7-e272-4795-8dec-c7f57d6b044f" width="50%" alt="Picture 2.9"/>

`Picture 2.9`

---

## Ransomware 205 — 🚫 Outdated
These steps were part of earlier BOTS v1 material, but the supporting data/events are no longer present in the current dataset.  
👉 They have been intentionally skipped in this walkthrough.

---

## Ransomware 206 — File Server IPv4
Bob Smith's workstation `we8105desk` was connected to a file server during the ransomware outbreak. What is the IPv4 address of the file server? <br /> 
- We can stay in the same query since we were looking at the Windows registry of the host we8105desk. 
- We replace the "friendlyname" name filter with "fileshare".
- We can see host = we8105desk is connecting to #192.168.250.20#fileshare
- Enter Search: index=botsv1 sourcetype="winregistry" host=we8105desk fileshare

Goal: Identify the file server we8105desk connected to during the outbreak.
**SPL**
```
index=botsv1 sourcetype=winregistry host=we8105desk earliest=08/24/2016:00:00:00 latest=08/25/2016:00:00:00 fileshare
| table _time host data_*
| sort _time
```
Validate: Confirm server IP in Registry values.
- [ ] **Answer:** `192.168.250.20`

<img src="https://github.com/user-attachments/assets/93490f93-0c23-43de-adaf-dde888ff0d59" width="50%" alt="Picture 3.0"/>

`Picture 3.0`

---

## Ransomware 207 — Distinct PDFs Encrypted on the File Server
How many distinct PDFs did the ransomware encrypt on the remote file server? <br /> 
We can find the file server's name on the same line where we saw its IP.
- DestinationHostname = we9041srv
- We use it as a host and filter using the command *pdf. We saw 526 events.
- index=botsv1 host=we9041srv *.pdf
- We look at the distant value to count which file could have been encrypted in this list. We can use "dc" and "stat" and filter it using "Relative_Target_Name" in our command.
-  | stats dc(Relative_Target_Name)
- Enter Search: index=botsv1 host=we9041srv *.pdf | stats dc(Relative_Target_Name)

Goal: Count distinct PDFs encrypted on we9041srv.
Answer guidance: Return a count (integer only).
**SPL**
```
index=botsv1 host=we9041srv "*.pdf" earliest=08/24/2016:00:00:00 latest=08/25/2016:00:00:00
| stats dc(Relative_Target_Name) as distinct_pdfs
```
Validate: Sample a few names to confirm they’re unique.
- [ ] **Answer:** we9041srv or `526`

<img src="https://github.com/user-attachments/assets/a9a5ad65-596d-4b26-a639-ccc70904113b" width="50%" alt="Picture 3.1"/>

`Picture 3.1`

<img src="https://github.com/user-attachments/assets/c8adc787-496c-4d0e-b8bf-518a12e7ee6e" width="40%" alt="Picture 3.2"/>

`Picture 3.2`

---

## Ransomware 208 — ParentProcessId for VBScript → 121214.tmp
The VBScript found in question 204 launches 121214.tmp. What is the ParentProcessId of this initial launch? `Pictures 1.1 – 1.4` <br /> 
Since we know the file name, we can return to the query we saved from step 204.
- Filter the scripts by adding the file name and looking at the parent_process_id field.
- Enter Search:  index=botsv1 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" *.vbs 121214.tmp

Goal: Find the ParentProcessId that launched 121214.tmp from VBS.
Answer guidance: Enter PPID as an integer, e.g., 3968.
**SPL**
```
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" ("*.vbs" OR "121214.tmp") earliest=08/24/2016:00:00:00 latest=08/25/2016:00:00:00
| table _time host Image ParentImage ProcessId ParentProcessId CommandLine
| sort _time
```
Validate: Ensure the parent/child chain aligns with the first execution time.
- [ ] **Answer:** `3968`

<img src="https://github.com/user-attachments/assets/ad3c9595-bfe2-472c-98a3-1c9bb6f5d3c0" width="30%" alt="Picture 3.3"/>

`Picture 3.3`

---

## Ransomware 209 — .txt Files Encrypted in Bob’s Profile
The Cerber ransomware encrypts files located in Bob Smith's Windows profile. How many .txt files does it encrypt? <br /> 
- We can return to our earlier query, where we have Bob's hostname and directory.
- We can add ".txt" to his directory and use the "stats dc" command to improve our results.
- If you want his directory location for the search, click on his directory.
- Enter Search: index="botsv1" host=we8105desk sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" TargetFilename="C:\\Users\\bob.smith.WAYNECORPINC\\*.txt" | stats dc(TargetFilename)

Goal: Count distinct .txt files encrypted under Bob’s user profile.
**SPL**
```
index=botsv1 host=we8105desk sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" \
TargetFilename="C:\\Users\\bob.smith.WAYNECORPINC\\*.txt" earliest=08/24/2016:00:00:00 latest=08/25/2016:00:00:00
| stats dc(TargetFilename) as distinct_txt
```
Validate: Spot-check a few paths to confirm they’re user-profile files.
- [ ] **Answer:** `406`

<img src="https://github.com/user-attachments/assets/457b12dc-67f9-4cdd-baec-20592d907094" width="50%" alt="Picture 3.4"/>

`Picture 3.4`

---

## Ransomware 210 — Name of Downloaded Cryptor
The malware downloads a file that contains the Cerber ransomware cryptor code. What is the name of that file? <br /> 
- To get the file name, we head back to Suricata and inspect the network packets. 
- We can look at the raw text of the suspicious domain we found earlier. We found a .jpg.
- Enter Search: index=botsv1 sourcetype=suricata dest_ip="192.168.250.100"  "http.hostname"="solidaritedeproximite.org"
> Answer guidance: Please include the file name with extension.

Goal: Identify the downloaded file that contains Cerber’s cryptor code.
Answer guidance: Include the file name with extension, e.g., notepad.exe or favicon.ico.

**SPL**
```
index=botsv1 sourcetype=suricata dest_ip="192.168.250.100" "http.hostname"="solidaritedeproximite.org" earliest=08/24/2016:00:00:00 latest=08/25/2016:00:00:00
| eval filename=coalesce(fileinfo.filename, http.uri)
| table _time http.hostname http.uri filename
| sort _time
```
Validate: Check related Suricata events for the full URI trail.
- [ ] **Answer:** `mhtr.jpg`

<img src="https://github.com/user-attachments/assets/99ea1310-ba89-40fa-a9e1-94ece3814761" width="40%" alt="Picture 3.5"/>

`Picture 3.5`

<img src="https://github.com/user-attachments/assets/150a20dd-7ae2-431e-a4f6-b67596ac26a7" width="50%" alt="Picture 3.6"/>

`Picture 3.6`

---

## Ransomware 211 — Likely Obfuscation Technique
Now that you know the name of the ransomware's encryptor file, what obfuscation technique is it likely to use? <br /> 
- From here, we grab the field hash. We can use an analyzer like Virustotal.com.
- This type of technique is commonly used. 
- A quick search can reveal how this kind of file has been decoded in the past. We just needed the URL.

Goal: Infer the obfuscation technique used by the cryptor file.
**SPL**
```
index=botsv1 sourcetype=suricata dest_ip="192.168.250.100" earliest=08/24/2016:00:00:00 latest=08/25/2016:00:00:00
| search http.hostname="solidaritedeproximite.org" OR fileinfo.filename=* OR fileinfo.md5=* OR fileinfo.sha256=*
| table _time http.hostname http.uri fileinfo.filename fileinfo.md5 fileinfo.sha256
```
Validate: Enrich the hash in VT/OTX; note image-carrier behavior.
- [ ] **Answer:** `Steganography`

<img src="https://github.com/user-attachments/assets/be99b708-c5fe-4929-8343-09d6c03a9c6d" width="50%" alt="Picture 3.7"/>

`Picture 3.7`

<img src="https://github.com/user-attachments/assets/da0a82ab-1698-4051-bc22-1460114541c9" width="50%" alt="Graph 11"/>

---

## 🔄 **Recap — Step by Step**
| Phase                     | Implementation                                                       | Purpose                                   |
| ------------------------ | -------------------------------------------------------------------- | ----------------------------------------- |
| Bound the Window         | Mark first alert/user report + last known-good for `we8105desk`      | Keep searches tight and relevant          |
| Identify Patient-Zero    | Confirm host/IP (e.g., `we8105desk` → `192.168.250.100`)             | Anchor the hunt to a single endpoint      |
| Early DNS Signals        | Timeline suspicious FQDNs (filter benign *.local/*.arpa/MS domains)  | Catch ransomware infra early              |
| Payload Delivery         | Correlate Suricata/HTTP → cryptor fetch (e.g., `mhtr.jpg`)           | Prove how the encryptor arrived           |
| Process Lineage          | Sysmon chain (e.g., `VBScript → 121214.tmp`, capture PPID)           | Tie execution to parent/child processes   |
| Encryption Signals       | Spikes in file creates/renames + new extensions in user profile      | Confirm active encryption on host         |
| Lateral Movement / SMB   | File-server access (e.g., `we9041srv`) + distinct files encrypted    | Measure spread and business impact        |
| Removable Media Evidence | WinRegistry artifacts (USB friendly name like `MIRANDA_PRI`)          | Validate initial vector (USB lure)        |
| Collect IoCs & Evidence  | FQDNs, IPs, hashes, filenames, screenshots, exact timestamps         | Support containment and post-mortems      |
| Contain & Recover        | Isolate host, block IoCs, disable accounts, restore from backups     | Stop spread and return to good state      |
| Harden                   | DNS egress rules, ASR/AppLocker, macro blocking, least-priv SMB      | Reduce recurrence / shrink attack surface |
| Operationalize           | Saved searches, alerts/dashboards, backup validation & runbook       | Make response repeatable and faster       |

---

## 📚 **Lessons Learned**
- [ ] **Early DNS pays off:** Filtering benign domains surfaces ransomware infra quickly.  
     - DNS timelines gave first touchpoints before heavy encryption noise appeared.
- [ ] **Process lineage matters:** Parent/child chains cut through endpoint noise.  
     - VBS → TMP → encryptor established causality you can act on.
- [ ] **Velocity > volume:** Write-rate spikes + new extensions are high-signal.  
     - Baselines made the abnormal file creation jumps obvious.
- [ ] **Registry is gold for ingress:** USB artifacts confirmed the lure.  
     - Friendly-name keys tied the story together.
- [ ] **Quantify impact:** Distinct files encrypted on shares guide triage/comms.  
     - Counts per host/share prioritize isolation and recovery.
- [ ] **Repeatability wins:** Turn ad-hoc hunts into alerts/dashboards & RBA.  
     - Codifying detections shrinks MTTR and improves consistency.
- [ ] **Evidence discipline:** IoCs + screenshots + exact times enable audits & clean handoffs.  
     - Makes IR documentation and lessons-learned actionable.

---

## **Conclusion**
This lab turns a messy outbreak into a timeline of compromise → containment → hardening. By correlating DNS, Suricata, Sysmon, and Registry artifacts, we identified patient-zero, traced payload delivery, measured impact on the file server, and produced repeatable detections.

The same rhythm applies in production: observe → correlate → validate → harden. Practicing it here builds the muscle memory to respond faster when the stakes are real.

Next: Extend to Risk-Based Alerting (weight DNS + write spikes + lineage) and add SOAR actions for rapid isolation and backup validation.

<img width="1536" height="864" alt="image" src="https://github.com/user-attachments/assets/7c07939c-16f6-459d-962d-f7e3724243ec" />




