# Goal:
Detect an advesary utilizing the `SetWindowsHookEx` API to load a malicous DLL into a processes address space. 


# Categorization:
[Privilege Escalation/T1055/Process Injection](https://attack.mitre.org/techniques/T1055/)

# Strategy Abstract:
The strategy will function as follows:
- Collect events that correlate with data source Process Monitoring
- Alert an advesary utilizing API calls - CreateProcess, ZwUnmapViewOfSection OR NtUnmapViewOfSection, VirtualAllocEx, WriteProcessMemory, SetThreadContext, ResumeThread 
 to execute arbitrary code in the address space of an already running process.


## Logging:
| Event ID | Event Name | Data Source | Log Provider |
|---------|---------|----------|----------|
| [1](https://github.com/hunters-forge/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-1.md) | Process Creation | Process Monitoring | Sysmon Event Logs |
| [5](https://github.com/hunters-forge/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-5.md) | Process Termination  | Process Monitoring | Sysmon Event Logs |
| [10](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-10.md) | Process Access | Process Monitoring | Sysmon Event Logs |
| [7](https://github.com/hunters-forge/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-7.md) | Image Loaded  | Loaded DLL's | Sysmon Event Logs |


## Data Analytics:
| Analytic Platform | Analytic Type  | Analytic Logic | Additional Information |
|--------|---------|---------|---------|
| Kibana | Rule | `Need to add` | Need to make a KSQL stream JOIN. 
| Splunk | Rule | ` Need to Add ` | None
| SparkSQL | Rule | `SELECT
`| Create a JOIN on the both event ID 1 and 10's SourceProcessGUID along with both event's TargetProcessGUID

'''
SELECT 
    b.host_name,
    b.process_parent_name,
    a.process_target_name,
    a.process_granted_access,
    a.user_reporter_name
FROM sysmon_events b
JOIN sysmon_events a
    ON a.process_target_guid = b.process_guid
    AND a.event_id = 10
    AND a.process_granted_access = "2097151" -- Assuming they are asking for full privileges. Was hard to narrow down the minimum rights needed to perform. API's were not specefic. 
    AND b.process_parent_name = a.process_name
    AND a.process_name != b.process_name
JOIN sysmon_events c
    ON b.process_guid = c.process_guid
    AND c.event_id = 13
    AND c.process_guid = a.process_target_guid
    AND c.process_name = a.process_target_name 
    AND (substring_index(c.registry_key_path, '\\\\', -1)) = b.process_name
JOIN sysmon_events d
    ON d.process_guid = a.process_target_guid
    AND d.event_id = 7
    AND d.module_loaded = a.process_target_path
    AND LOWER(d.OriginalFileName) = (substring_index(c.registry_key_path, '\\\\', -1))
    AND d.OriginalFileName = b.OriginalFileName
WHERE
     b.event_id = 1
    AND b.process_name = LOWER(b.OriginalFileName)
    AND (NOT (b.process_name = "rundll32.exe" AND b.process_parent_name = "svchost.exe")) -- Blind spot + Assumption
    AND (NOT (b.process_name = "notepad.exe" AND b.process_parent_name = "explorer.exe")) -- Blind spot + Assumption
    AND (NOT (b.process_name = "devenv.exe" AND b.process_parent_name = "explorer.exe")) -- Blind spot + Assumption
    AND (NOT (b.process_name = "cmd.exe" AND b.process_parent_name = "explorer.exe")) -- Blind spot + Assumption
'''

# Techinical Context:
Within the Windows Operating System, there a mechanism that allows functions, events, messages, and user input to be intercepted. This is mechanism is called a `hook`. A `hook procedure` is when a function intercepts a specefic type of event. 
Adversaries can 
- Utilize `LoadLibrary` to load a malicious DLL in the address space of an already running process. 
- Use `GetProcAddress` to retrieve the address for where they want to inject the malicious dll.  
- Then use the  `SetWindowsHookEx` API to create a hook routine in to the hook chain. 
After the function call for which the hook was set is called and intercepted, the malware will execute its malicious code into the thread that was passed to `SetWindowsHookEx`. This is a way for an adversary to target a process that is running and inject malicious code into it. Effectively using that process to perform future tasks. 

# Blind Spots and Assumptions:
* Advesary is using another form of process injection - DLL injection, process hallowing, etc.
* Any of the processes that are being excluded are performing the original hook. 

## Assumption: 
* The processes above aren't being used as part of the attack. 

## Blind Spot:
* Advesary doesn't utilize the above APIs to inject arbitrary code into a process. 


# False Positives:
* Processes starting at Windows Startup that are hooking on functions to perform tasks. 
# Validation:

# Priority:
The priority is set to medium


# Response:
* Kill any threads that were creatted in the process that have been injected into.
* Monitor behavior of the  parent processes of the injected process to check for further malicious activity. 
* Further investigate the user’s activity that was used to perform the attack, for additional malicious activity. 
    * This can give additional context, if this user was used to perform another attack technique on the host. 
        * Lateral Movement to another host or user. 
        * Credential Dumping of system’s users. 
        * Persistent scripts being ran. 


# Resources:
* [DLL Injection Part 1: SetWindowsHookEx](https://warroom.rsmus.com/dll-injection-part-1-setwindowshookex/)

* [SetWindowsHookExA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexa)

* [Sysmon](https://github.com/Cyb3rWard0g/OSSEM/tree/master/data_dictionaries/windows/sysmon)

* [Endgame 10 Process Inejection Techniques](https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)

* [Mitre ATT&CK - Process Injection](https://attack.mitre.org/techniques/T1055/)
