# Goal:
Detect an advesary utilizing API calls - `CreateRemoteThreadEx` and `OpenProcess` to execute arbitrary code in the address space of an already running process.


# Categorization:
[Privilege Escalation/T1055/Process Injection](https://attack.mitre.org/techniques/T1055/)

# Strategy Abstract:
The strategy will function as follows:
- Collect events that correlate with data source Process Monitoring
- Alert an advesary utilizing API calls - `CreateRemoteThreadEx` and `OpenProcess` to execute arbitrary code in the address space of an already running process.

## Logging:
| Event ID | Event Name | Data Source | Log Provider |
|---------|---------|----------|----------|
| [8](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-8.md) | CreateRemoteThread was detected  | Process Monitoring | Sysmon Event Logs |
| [10](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-10.md) | Process Access | Process Monitoring | Sysmon Event Logs |

## Data Analytics:
| Analytic Platform | Analytic Type  | Analytic Logic | Additional Information |
|--------|---------|---------|---------|
| Kibana | Rule | `Need to add` | Need to make a KSQL stream JOIN. 
| Splunk | Rule | ` Need to Add ` | None
| SparkSQL | Rule | `SELECT  b.process_path, b.process_target_name, b.process_target_id, b.thread_new_id, a.process_id, a.process_granted_access FROM sysmon_events b INNER JOIN( SELECT event_id, process_granted_access, process_guid, process_id FROM sysmon_events  WHERE event_id = 10 AND (process_granted_access & 5184) == 5184 -- 5184 is decimal for 0x1440. The minimal privileges you need to access process handle) a ON a.process_guid = b.process_guid WHERE b.event_id = 8`| Create a JOIN on the both event ID 8 and 10's SourceProcessGUID along with both event's TargetProcessGUID

# Techinical Context:
A DLL is a dynamic link library file that is used to hold code and procedures for Windows programs. An advessary can create malicious code in the format of a DLL. Reflective DLL Injection allows an adversary to load a DLL from memory vs. from disk. Adversaries can enumerate running processes on a system, then can execute arbitrary code by injecting a DLL into the address space of a target process. By doing so, the adversary can run their code under the context of any target process they choose. The process flow of this is as follows:

```
1. Adversary targets a process for injection.
2. Adversary calls OpenProcess to get a handle on the target process.
3. Adversary calls VirtualAllocEx to have an address space in the remote process to write the reflective DLL.
4. Adversary calls WriteProcessMemory to write the reflective DLL into the allocated memory from above.
5. Adversary calls CreateRemoteThreadEx, pointing to the region specified by VirtualAllocEx to begin execution of the reflective DLL.
```
Based off of this behavior, there are 2 APIs that correlate with 2 Sysmon events can be used for detection:

1. Sysmon Event ID 8 - CreateRemoteThread Detected. This event will call the event registraion mechanism: `PsSetCreateThreadNotifyRoutine`, which is a kernel callback function inside of Windows. Inside of the Sysmon driver, the `CreateRemoteThreadEx` API is funneled through this event registration mechanism to create an ID of 8. 
The advesary needs to call CreateRemoteThread to execute the DLL they used to write into the targeted process.  

2. Sysmon Event ID 10 - Process Access. This event will call the event registraion mechanism: `ObRegisterCallbacks`, which is a kernel callback function inside of Windows. Inside of the Sysmon driver, the `nt!NtOpenProcess ` API is funneled through this event registration mechanism to create an ID of 10. 
The advesary needs to open the process that the thread belongs to interact with the newly injected thread. 

Although there are 2 APIs that correlate with Sysmon event IDs, there are 4 Window API calls being utilized within this techniques behavior. To better understand the behavior of this malicious activity, it would be good to map out the minimal privileges an adversary needs to access a process handle, while using these APIs.
To map out the minimal privileges an adversary need to access process handle, I went to each APIs documentation within Microsoft and mapped out which privileges are needed to access the process handle. The following privileges are needed:
``` 
PROCESS_CREATE_THREAD (0x0002)
PROCESS_QUERY_INFORMATION (0x0400)
PROCESS_QUERY_LIMITED_INFORMATION (0x1000) — Automatically granted if a handle that has the PROCESS_QUERY_INFORMATION
PROCESS_VM_OPERATION (0x0008)
PROCESS_VM_WRITE (0x0020)
PROCESS_VM_READ 0x0010)
 ```
After adding these privileges up, the minimal rights needed to access a process handle is: (0x1440).

# Blind Spots and Assumptions:
* Advesary is using another form of process injection - DLL injection, process hallowing, etc.

## Assumption: 
* API's `CreateRemoteThreadEx`, `NtOpenProcess` are being called during process injection. 
* Advesary is utilizing these APIs to inject arbitrary code into a process. 

## Blind Spot:
* Advesary doesn't utilize the above APIs to inject arbitrary code into a process. 


# False Positives:
* Can not find legitimate use cases for `CreateRemoteThread`. 

# Validation:
Invoke-PSInject 

# Priority:
The priority is set to medium


# Response:
* In the event that this alert fires, run the supplied script - `GetInjectedThread` by Jared Atkinson on the host that fired this alert. 
* Kill any threads that were creatted in the process that have been injected into.
* Monitor behavior of the  parent processes of the injected process to check for further malicious activity. 
* Further investigate the user’s activity that was used to perform the attack, for additional malicious activity. 
    * This can give additional context, if this user was used to perform another attack technique on the host. 
        * Lateral Movement to another host or user. 
        * Credential Dumping of system’s users. 
        * Persistent scripts being ran. 


# Resources:
* [CreateRemoteThreadEx](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethreadex)

* [Get-InjectedThread](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

* [Sysmon](https://github.com/Cyb3rWard0g/OSSEM/tree/master/data_dictionaries/windows/sysmon)

* [Process Injection blog](https://medium.com/@jsecurity101/injecting-into-the-hunt-185af9d56636)

* [Endgame 10 Process Inejection Techniques](https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)

* [Mitre ATT&CK - Process Injection](https://attack.mitre.org/techniques/T1055/)

