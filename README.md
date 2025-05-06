# 🛡️ Real-World Ransomware Investigation with Splunk

## Overview
This case study was part of the **Boss of the SOC (BOTS)** Splunk Blue Team CTF challenge—designed to test real-world incident response and threat hunting skills.

I took the role of a Security Analyst in a live-ransomware attack simulation, where my goal was to investigate a Cerber ransomware infection. I used a methodical, evidence-based approach across host and network logs using Splunk. Each challenge was solved independently by framing hypotheses, querying Splunk effectively, and using smart pivots with human reasoning and real-world logic.

🧠 **Goal**: Recreate a professional-grade SOC investigation to uncover attacker tactics and build a complete timeline.

🔧 **Tools Used**: Splunk, Sysmon, Registry Logs, DNS, HTTP, Suricata, Fortigate UTM

---

## 🔍 Challenge 1: Identify Victim IP
**Objective**: What was the IP of `we8105desk` on 24 AUG 2016?
```spl
index=botsv1 we8105desk sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats count by src_ip src dest_ip host
```
💡 **My Thinking**: Start from hostname → find logs referencing IP → validate via stats. 
✅ **Finding**: Victim's IP = `192.168.250.100`

📝 Key strategy: Always check `src_ip` over `src` for precision.

![image](https://github.com/user-attachments/assets/53ae058c-e9ec-4651-af16-193c8ccc3fcf)

![image](https://github.com/user-attachments/assets/e0a8989d-2930-4d59-a34a-746d8e94b211)

---

## 💾 Challenge 2: USB Inserted
**Objective**: What was the name of the USB device inserted?
```spl
index=botsv1 sourcetype=winregistry friendlyname
| table host object data
```
💡 **My Thinking**: Look into Registry logs—USB logs often logged under `friendlyname`. 
✅ **Finding**: USB = `MIRANDA_PRI`

📝 Emotion: “I smiled when I found only 2 events—sometimes simple terms go a long way.”

![image](https://github.com/user-attachments/assets/913d48d9-ba11-4742-a312-b12c3495b719)

![image](https://github.com/user-attachments/assets/0c31d2e5-a270-4419-8a5a-5b276123e51f)

---

## ⚠️ Challenge 3: Malicious File Executed
**Objective**: What file was executed from the USB and what were its child processes?
```spl
index=botsv1 sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational host=we8105desk "d:\\"
| reverse
```
💡 **My Thinking**: If it's USB-borne malware, the path won’t be `C:\`, but `D:\`. Also, attackers love `dotm` macros.
✅ **Finding**: File = `miranda_tate_unveiled.dotm`
- Child Processes: `cmd.exe`, `splwow64.exe`

📝 Dotm → Word → CMD = Classic Macro Infection.

![image](https://github.com/user-attachments/assets/4ff58594-2e18-4384-bbf3-2b3224f7b460)

![image](https://github.com/user-attachments/assets/2084df32-0b0a-4650-8721-df8d3645583c)

---

## 🧬 Challenge 4: Suspicious VBScript Length
**Objective**: What was the length of the command line string?
```spl
index=botsv1 sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational host=we8105desk EventCode=1 CommandLine=*
| eval length=len(CommandLine)
| table CommandLine length
| sort - length
```
💡 **My Thinking**: Longest strings = Obfuscated payloads. Go for length, then inspect manually.
✅ **Finding**: Length = `4490`

📝 Smart trick: Add `CommandLine=*` to exclude nulls.

![image](https://github.com/user-attachments/assets/433b5a4a-4c79-4d81-9764-98b875d3481a)

![image](https://github.com/user-attachments/assets/73fa131b-fb79-4b46-8a7b-b971a967842d)


---

## 🖧 Challenge 5: File Server Connection
**Objective**: Which file server did the victim connect to?
```spl
index=botsv1 sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational host=we8105desk src=we8105desk.waynecorpinc.local
| stats count by dest_ip
```
💡 **My Thinking**: Track network connections with `dest_ip`. Then validate against Registry logs.
✅ **Finding**:
- IP = `192.168.250.20`
- Hostname = `we9041srv`

📝 Tip: Confirm file server IP via winregistry `fileshare` keyword.

![image](https://github.com/user-attachments/assets/f65f862b-66e5-4088-86a9-41139dc7218b)
![image](https://github.com/user-attachments/assets/be603c1b-10fb-4f1a-ab91-b8ff37b21e08)

![image](https://github.com/user-attachments/assets/594cb5d0-2903-44b8-9c77-406af965cab5)

![image](https://github.com/user-attachments/assets/c4584acc-540e-4b8e-9290-f1df76bb9a1b)

---

## 🌐 Challenge 6: First Suspicious Domain
**Objective**: Which suspicious domain was first visited?
```spl
index=botsv1 sourcetype=stream:DNS src=192.168.250.100 record_type=A
NOT (query{}=*.microsoft.com OR query{}=*.waynecorpinc.local OR ...)
| table _time query{}
| reverse
```
💡 **My Thinking**: Whitelist first (Microsoft, Bing, etc.) → Focus on suspicious domains left over.
✅ **Finding**: `solidaritedeproximite.org`

📝 This domain reappears later as part of download payloads.

![image](https://github.com/user-attachments/assets/f96c0b11-3bd4-42c7-a703-4de3c231b69f)

![image](https://github.com/user-attachments/assets/9035b7a8-e975-482b-9848-7304f9efedc3)

![image](https://github.com/user-attachments/assets/341fff5f-7315-4454-ba71-1066e3da0ab6)

![image](https://github.com/user-attachments/assets/7c47a742-65a0-4d43-8c65-34460f265507)

---

## 🧨 Challenge 7: Cryptor File Downloaded
**Objective**: What was the downloaded file?
```spl
index=botsv1 sourcetype=stream:http src=192.168.250.100 url=*mhtr.jpg*
```
💡 **My Thinking**: JPG file download? Suspicious! Validate with Suricata & UTM.
✅ **Finding**:
- File: `mhtr.jpg`
- Alert: `cerber.botnet`

📝 Strategy: Confirm via 3 sources (http, suricata, fgt_utm)

![image](https://github.com/user-attachments/assets/7d3029e3-175d-4517-aa61-3c055f3487eb)

![image](https://github.com/user-attachments/assets/410a1b55-3ad0-445a-83d7-8dbc27ad1b31)

![image](https://github.com/user-attachments/assets/3f1d2421-5d46-4c90-9d57-fd6ac3da6b93)

![image](https://github.com/user-attachments/assets/84f2d40a-02f9-45b0-a764-bfe534b2ac3e)

![image](https://github.com/user-attachments/assets/985e28c7-dcd5-4534-9ae8-90269218ed22)

---

## 🔗 Challenge 8: TMP File Process Chain
**Objective**: What was the parent PID of `121214.tmp`?
```spl
index=botsv1 sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational 121214.tmp CommandLine=*
| table _time CommandLine ProcessId ParentProcessId ParentCommandLine
```
💡 **My Thinking**: Track process lineage—child of VBS, grandchild of Word.
✅ **Finding**: PID = `3968`

📝 Chain: `wscript` → `vbs` → `cmd` → `tmp` → fake `osk.exe`

![image](https://github.com/user-attachments/assets/47ea33cd-ac0e-4c63-8cf0-0ee7dbd2a32f)

![image](https://github.com/user-attachments/assets/1746a9c6-ba38-43e7-9f60-f248aeddbefd)

---

## 🧾 Challenge 9: Least Alerting Suricata Signature
**Objective**: Which signature alerted the fewest?
```spl
index=botsv1 sourcetype=suricata alert.signature=*cerber*
| stats count by alert.signature alert.signature_id
| sort count
```
💡 **My Thinking**: Use `alert.signature_id` to track precision. Check timing.
✅ **Finding**:
- ID: `2816763`
- First Seen: `16:49:24`, Last Seen: `17:15:12`

📝 This helped shape timeline of payload delivery.

![image](https://github.com/user-attachments/assets/f0bd44ae-da07-4c2d-a0b1-f36c3ae03f90)

![image](https://github.com/user-attachments/assets/2f8937fe-71f1-4b80-99aa-63e3a8acdb1c)
![image](https://github.com/user-attachments/assets/77ce7a86-4dad-4d5d-bded-94aa8c1f9b6b)

---

## 📂 Challenge 10: TXT Files Encrypted (Local)
```spl
index=botsv1 sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational host=we8105desk EventCode=2 TargetFilename="C:\\Users\\bob.smith.WAYNECORPINC\\*.txt"
| stats dc(TargetFilename)
```
💡 **My Thinking**: Ransomware often hits `Documents`, `Desktop`, `AppData`. Focused on Bob's profile.
✅ **Finding**: 406 `.txt` files encrypted

📝 Always use double backslashes in paths in Splunk.

![image](https://github.com/user-attachments/assets/2a5f5a1e-c436-4015-8565-0013ed4ccf63)

![image](https://github.com/user-attachments/assets/5813fb9b-a518-422d-8e94-91d85a66cb93)

![image](https://github.com/user-attachments/assets/c8d272a5-a23b-436a-9757-0d1b625fea73)

![image](https://github.com/user-attachments/assets/a97e5dff-5b77-433e-a149-0364865a1c85)

![image](https://github.com/user-attachments/assets/d2b38a1c-0a10-4750-ad65-c5ed412bcce3)

---

## 🗄️ Challenge 11: Encrypted PDFs on Remote File Server
```spl
index=botsv1 sourcetype=*win* pdf dest=we9041srv.waynecorpinc.local Source_Address=192.168.250.100
| stats dc(Relative_Target_Name)
```
💡 **My Thinking**: Use `Relative_Target_Name` for file types on remote shares.
✅ **Finding**: 257 `.pdf` files encrypted

📝 Shows lateral spread beyond the initial victim.

![image](https://github.com/user-attachments/assets/2b1ae995-145e-4e5b-8110-445106cd2665)

![image](https://github.com/user-attachments/assets/e1678061-16c9-472f-97d1-dcd74b27e802)

![image](https://github.com/user-attachments/assets/d2d2406d-c250-4db2-8a31-58e7e5f808ec)

![image](https://github.com/user-attachments/assets/df506729-89c0-4843-8348-f5983608362e)

![image](https://github.com/user-attachments/assets/323f0b4a-371f-4a3a-983f-bca9309ca4cf)

---

## 🧭 Challenge 12: Final FQDN Redirect Post-Encryption
```spl
index=botsv1 sourcetype=stream:DNS src=192.168.250.100 record_type=A
NOT (query{}=*.microsoft.com OR ...)
| table _time query{}
| reverse
```
💡 **My Thinking**: Last DNS request = ransom site. Strip known domains → check what’s left.
✅ **Finding**: `cerberhyed5frqa.xmfir0.win`

📝 Used NOT conditions to quickly isolate strange domains.

![image](https://github.com/user-attachments/assets/b23b0301-eaca-4b68-9848-ead8f88819d4)

![image](https://github.com/user-attachments/assets/19f76e8d-068f-4fc7-ae6e-3c4fe81c3f35)

---

## 🧠 Summary: Threat Chain
1. 🎯 USB `MIRANDA_PRI` inserted
2. 📄 Macro in `dotm` file launched `cmd`, `splwow64`
3. 🦠 VBS file triggered `.tmp` → fake `osk.exe`
4. 🌍 DNS query to `solidaritedeproximite.org`
5. 📥 File `mhtr.jpg` downloaded from malicious server
6. 🚨 Alert fired: `cerber.botnet`
7. 🔐 406 TXT and 257 PDFs encrypted
8. 🔗 User redirected to: `cerberhyed5frqa.xmfir0.win`

---

## 💡🎯 Threat Picture and Timeline:

![image](https://github.com/user-attachments/assets/20783c4d-ea1a-45ad-9769-6c9cd2a1335c)


