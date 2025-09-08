# QueryingFundamentals
Repo contains information on how to query for information regardless of which SIEM you utilize. 

As I finished several blue team CTFs... I figured it's a good time to write up on how to query for information. As a beginner and someone who actively participates in Blue Team CTFs.. you are doing investigations that requires you to utilize the SIEM and various tools to investigate the "infected" endpoint or endpoints. When I first started learning about SIEMs and actively participated in BTLO labs... I realized I knew very little on how to query for information. Think about it, as soon as you index and put in a wildcard... you immediately see 1 million logs and you are freaking out because there's so many to analyze. Well, this is where querying fundamentals and your knowledge of network/operating systems come in. In this repo, I will go over some fundamentals and reference you to a github created by ThatTotallyRealMyth that will assist you in hunting for EVIL in those BlueTeamCTFs or in the real world setting. 
# Important Information
Understand what you are looking for. This is important. If you're in a SOC environment... I predict that you have alerts already set up in the EDR or SIEM so you have to work off whatever alert your EDR/SIEM is showing. For blue team ctfs... you won't have any alerts. They will give you some random scenario that emulate the real world to some degree. You have to figure out what actually happened by these simulated threat actors and answer the questions according to the CTF. 

# Example 1 with Remote Logon
Here's an example to look at. On 12/15/2024 a threat actor remoted in from a random IP address. What are the logs I need to pull up regarding that event? 

For one, I have to set my SIEM timeline to look between for 12/15/2024 and 12/16/2025. I am immediately thinking about windows security logs for successful logon.. and Remote Desktop Protocol. You can easily look it up on google if you don't remember. 

Here's a splunk query since it's fairly common
index=* source="xmlwineventlog:microsoft-windows-security" EventCode=4624 earliest=12/15/2024:00:00:00 latest=12/16/2024:00:00:00
(LogonType=3 or LogonType10) dest_port=3389
| sort +_time
| table _time EventCode user dest_port dest_ip
# Explanation for Example 1
Why is my splunk query the way that it is?

The first is I am referencing windows security logs because it contains information regarding successful logon, and since windows security logs is the source, I typed source="xmlwineventlog:microsoft-windows-security". This may be different in some of your SIEMs... but it should relatively be similar.  In this case, Windows Event ID 4624 indicates that somebody logged into the machine successfully. Next is Logon Type, type 3 indicates network connection, type 10 indicates RDP.

Next is destination port, since I know RDP is port 3389, I have asked the SIEM to pull up any connection from port 3389 so dest_port=3389. Then have it organize and display the information I need, hence | table _time EventCode user dest_port dest_ip.  Table displays the information I want which is the time, EventCode, the User, destination port, and the destination IP (so where is my connection going to). You do want to document anything relevant as well as the time. You can't tell if the Threat Actor accessed your environment and what they did without documenting the time.
# Example 2 with File Execution
Now, let's just say the person that remoted in deployed a malicious file. What would I query for in that case? Well immediately I'm looking up any event ID that's pertaining to process creation. Same base, just now query for something different.

index=* source="xmlwineventlog:microsoft-windows-security" User="Compromised Account" NOT User="NT AUTHORITY\\SYSTEM"
 EventCode=4688 earliest=12/15/2024:00:00:00 latest=12/16/2024:00:00:00
| sort +_time
| table _time EventCode user ProcessName ParentCommandLine ParentImage ProcessCommandLine OriginalFileName Hashes
# Explanation for Example 2
This time why display ProcessName, ParentCommandLine, ProcessCommandLine, OriginalFileName, Hashes? For one, I want to know the process that spawned, from which commandline and directory, and hashes of the file so I can look it up on VirusTotal/Hybrid Analysis. ParentCommandLine... is the "Parent" aka the command that creates the process. If there's no parent command line, I will check for the parent Image which is the executable or process that launched another process. This is particularly helpful to determine the chain of events especially with file activity. 
# Conclusion
When querying, it all depends on what information the analyst/CTF player wants. This is where having a critical understanding of network and operating system fundamentals is important especially understanding how the registry, DLLs, and various files work. You can't hunt for threats if you don't know what is normal. Every CTF/Organization has different baselines. It's up to you as the individual to put it into context. I hope this helps anybody who struggled to query for information like I did. 

# Reference to the Github by ThatTotallyRealMyth w/ Splunk/SIEM queries
https://github.com/ThatTotallyRealMyth/GhostHuntingInSplunk
