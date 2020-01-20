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
| [1](https://github.com/hunters-forge/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-1.md) | CreateProcess was detected  | Process Monitoring | Sysmon Event Logs |
| [10](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-10.md) | Process Access | Process Monitoring | Sysmon Event Logs |


## Data Analytics:
| Analytic Platform | Analytic Type  | Analytic Logic | Additional Information |
|--------|---------|---------|---------|
| Kibana | Rule | `Need to add` | Need to make a KSQL stream JOIN. 
| Splunk | Rule | ` Need to Add ` | None
| SparkSQL | Rule | `SELECT
`| Create a JOIN on the both event ID 1 and 10's SourceProcessGUID along with both event's TargetProcessGUID

```
SELECT
	f.process_parent_name,
	f.process_name,
	a.logon_type
	f.user_logon_id
	z.user_logon_id
	f.host_name
FROM security_events a
JOIN security_events z
	ON a.user_logon_id = z.user_logon_id
	AND z.event_id = 4688
JOIN sysmon_events f
	ON z.process_name = f.process_name
	AND f.event_id = 1
	AND f.user_name = z.user_name
	AND f.user_logn_id != z.user_logon_id
JOIN sysmon_events c
	ON f.prcoess_guid = c.process_target_guid
	AND c.event_id = 10
	AND (c.process_granted_access & 40) == 40
	OR (c.process_granted_access & 80) == 80
	AND f.process_name = c.process_target_name
	AND f.process_parent_guid = c.process_guid
WHERE
	a.event_id = 4624
	AND a.logon_type = 11
	AND a.src_ip_addr is not null
```

# Techinical Context:
Process hollowing AKA RunPE is a process injection technique that creates a legitimate process in suspended state, deallocates the memory section of the process and replaces it with malicious code. Processes can be started in a suspended state with the API call `CreateProcess` and setting the Process Creation Flag to `CREATE_SUSPENDED`(0x00000004). The suspended process is then "hollowed out" via `ZwUnmapViewOfSection` or `NtUnmapViewOfSection`. The technique then uses the `VirtualAllocEx` API call to allocate the new memory segment and `WriteProcessMemory` to write that memory segment to the existing suspended process. The technique can then call `SetThreadContext` to point the entrypoint to a new code section that it has written. The suspended process cannot run until `ResumeThread` is called. 

By doing so, the adversary can run their code under the context of any target process they choose. The process flow of this is as follows:

```
1. Adversary calls CreateProcess (with CREATE_SUSPENDED (0x00000004) flag) to create a suspended process.
2. Adversary calls ZwUnmapViewOfSection or NtUnmapViewOfSection to remove mapped memory of the suspended process.
3. Adversary calls VirtualAllocEx to have an address space in the remote process to write the new memory segment.
4. Adversary calls WriteProcessMemory to write the new memory segment into the allocated memory from above.
5. Adversary calls SetThreadContext to point the entrypoint to a new code section that it has written.
6. Adversary calls ResumeThread to resume the suspended process.
```
Based off of this behavior, there are 2 APIs that correlate with 2 Sysmon events can be used for detection:

1. Sysmon Event ID 1 - CreateProcess Detected. This event will call the event registraion mechanism: `PsSetCreateProcessNotifyRoutine`, which is a kernel callback routine to, or removes it from, a list of routines to be called whenever a process is created or deleted. Inside of the Sysmon driver, the `CreateProcess` API is funneled through this event registration mechanism to create an ID of 1. 
The advesary needs to call CreateProcess to start a target process in a suspended state.  

2. Sysmon Event ID 10 - Process Access. This event will call the event registraion mechanism: `ObRegisterCallbacks`, which is a kernel callback function inside of Windows. Inside of the Sysmon driver, the `nt!NtOpenProcess ` API is funneled through this event registration mechanism to create an ID of 10. 
The advesary needs to open the suspended process to re-allocating memory segments. One of the unique characteristics of this specific process access event is that the `process granted Access` field displays the code `0x00000004` which corresponds to `CREATE_SUSPENDED`. The primary thread of the new process is created in a suspended state, and does not run until the `ResumeThread` function is called. Another function that an adversary could use is the `PROCESS_SUSPEND_RESUME (0x0800)` to resume the primary thread; as this too has been included in the query. 

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

* [Process Injection blog](https://medium.com/@jsecurity101/injecting-into-the-hunt-185af9d56636)

* [Endgame 10 Process Inejection Techniques](https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)

* [Mitre ATT&CK - Process Injection](https://attack.mitre.org/techniques/T1055/)
