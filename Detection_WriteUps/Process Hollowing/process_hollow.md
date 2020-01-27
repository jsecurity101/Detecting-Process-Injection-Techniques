# Goal:
Detect when an adversary creates a process in a suspended state, deallocates the memory section of the process and replaces it with malicious code. 


# Categorization:
[Privilege Escalation/T1093/Process Hollowing](https://attack.mitre.org/techniques/T1093/)

# Strategy Abstract:
The strategy will function as follows:
- Collect events that correlate with data source: process monitoring, loaded dll's.
- Alert an advesary utilizing API calls - CreateProcess, ZwUnmapViewOfSection OR NtUnmapViewOfSection, VirtualAllocEx, WriteProcessMemory, SetThreadContext, ResumeThread to execute arbitrary code in the address space of an already running process.


## Logging:
| Event ID | Event Name | Data Source | Log Provider |
|---------|---------|----------|----------|
| [1](https://github.com/hunters-forge/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-1.md) | CreateProcess was detected  | Process Monitoring | Sysmon Event Logs |
| [10](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-10.md) | Process Access | Process Monitoring | Sysmon Event Logs |
| [5](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-5.md) | Process Access | Process Monitoring | Sysmon Event Logs |
| [7](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-7.md) | Process Access | Loaded DLL's | Sysmon Event Logs |



## Data Analytics:
| Analytic Platform | Analytic Type  | Analytic Logic | Additional Information |
|--------|---------|---------|---------|
| Kibana | Rule | `Need to add` | Need to make a KSQL stream JOIN. 
| Splunk | Rule | ` Need to Add ` | None
| SparkSQL | Rule | `SELECT
`| Create a JOIN on the both event ID 1 and 10's SourceProcessGUID along with both event's TargetProcessGUID

```
SELECT 
    c.computer_name, 
    c.User,
    c.ParentImage,
    d.TargetImage,
    c.LogonId,
    ltrim('0x', d.GrantedAccess) as granted_access
FROM process_hollowing b  
JOIN process_hollowing c
    ON c.Image = b.NewProcessName
    AND c.channel = "Microsoft-Windows-Sysmon/Operational"
    AND c.event_id = 1
    AND b.SubjectUserName = (substring_index(c.User, '\\\\', -1))
JOIN process_hollowing d
    ON c.ProcessGuid = d.TargetProcessGUID
    AND d.channel = "Microsoft-Windows-Sysmon/Operational"
    AND d.event_id = 10
    AND c.ParentProcessGuid = d.SourceProcessGUID
    AND c.Image = d.TargetImage
JOIN process_hollowing e
    ON e.ProcessGuid = c.ParentProcessGuid
    AND e.channel = "Microsoft-Windows-Sysmon/Operational"
    AND e.event_id = 5
    AND e.Image = d.SourceImage
    AND c.ParentImage = e.Image
JOIN process_hollowing f
    ON f.ProcessGuid = c.ParentProcessGuid
    AND f.channel = "Microsoft-Windows-Sysmon/Operational"
    AND f.event_id = 7
    AND f.Image = c.ParentImage
    AND f.Image = f.ImageLoaded
WHERE b.channel = "Security"
    AND b.event_id = 4688
```

# Techinical Context:
Process hollowing is a process injection technique that creates a legitimate process in a suspended state, deallocates the memory section of the process and replaces it with malicious code. Processes can be started in a suspended state with the API call `CreateProcess` and setting the Process Creation Flag to `CREATE_SUSPENDED`(0x00000004). The suspended process is then "hollowed out" via `ZwUnmapViewOfSection` or `NtUnmapViewOfSection`. The technique then uses the `VirtualAllocEx` API call to allocate the new memory segment and `WriteProcessMemory` to write that memory segment to the existing suspended process. The technique can then call `SetThreadContext` to point the entrypoint to a new code section that it has written. The suspended process cannot run until `ResumeThread` is called. 

By doing so, the adversary can run their code under the context of any target process they choose. The process flow of this is as follows:

```
1. Adversary calls CreateProcess (with CREATE_SUSPENDED (0x00000004) flag) to create a suspended process.
2. Adversary calls ZwUnmapViewOfSection or NtUnmapViewOfSection to remove mapped memory of the suspended process.
3. Adversary calls VirtualAllocEx to have an address space in the remote process to write the new memory segment.
4. Adversary calls WriteProcessMemory to write the new memory segment into the allocated memory from above.
5. Adversary calls SetThreadContext to point the entrypoint to a new code section that it has written.
6. Adversary calls ResumeThread to resume the suspended process.
```
Based off of this behavior, there is 1 API that correlate with 1 Sysmon events can be used for detection:

Sysmon Event ID 1 - CreateProcess Detected. This event will call the event registraion mechanism: `PsSetCreateProcessNotifyRoutine`, which is a kernel callback routine to, or removes it from, a list of routines to be called whenever a process is created or deleted. Inside of the Sysmon driver, the `CreateProcess` API is funneled through this event registration mechanism to create an ID of 1. 
The advesary needs to call CreateProcess to start a target process in a suspended state.  

There are 3 other Sysmon events that do not correlate directly to the API's being called in the code: 
-  Sysmon Event ID 10 - Process Access. The advesary needs to open the suspended process to re-allocating memory segments. One of the unique characteristics of this specific process access event is that the `process granted Access` field displays the code `0x00000004` which corresponds to `CREATE_SUSPENDED`. The primary thread of the new process is created in a suspended state, and does not run until the `ResumeThread` function is called. Another function that an adversary could use is the `PROCESS_SUSPEND_RESUME (0x0800)` to resume the primary thread; as this too has been included in the query. 

- Sysmon Event ID 7 - Image Loaded. When the process is created, its image has to be loaded. 

- Sysmon Event ID 5 - Process Termination. When the sacrifical process that has been killed, it can correlate with the parent process of the process that the malicious code now sits.  

# Blind Spots and Assumptions:
* Advesary is using another form of process injection - DLL injection, process hallowing, etc.

## Assumption: 
* API's `CreateProcess`, `ZwUnmapViewOfSection or NtUnmapViewOfSection`, `VirtualAllocEx`, `SetThreadContext`, `ResumeThread` are being called during process injection. 
* Advesary is utilizing these APIs to inject arbitrary code into a process. 

## Blind Spot:
* Advesary doesn't utilize the above APIs to inject arbitrary code into a process. 


# False Positives:

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

* [Evading Get-Injected Thread](https://blog.xpnsec.com/undersanding-and-evading-get-injectedthread/)

* [Dectecing Process Hollowing- Memory Forensics](https://cysinfo.com/detecting-deceptive-hollowing-techniques/)

* [Github](https://github.com/djhohnstein/CSharpSetThreadContext)

* [Twitter](https://twitter.com/mattifestation/status/1113100995381297153)

* [Sysmon](https://github.com/Cyb3rWard0g/OSSEM/tree/master/data_dictionaries/windows/sysmon)

* [Endgame 10 Process Inejection Techniques](https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)

