# Goal:
Detect an advesary utilizing Transactional NTFS (TxF) to replace the memory of a legitimate process and executing malicious code. 


# Categorization:
[Defense Eveasion/T1186/Process Doppleganging](https://attack.mitre.org/techniques/T1186/)

# Strategy Abstract:
The strategy will function as follows:
- Collect events that correlate with the following data sources: 
    - File Monitoring
    - Process Monitoring
- Alert an advesary utilizes TxF to create a process. ***Might need to change**

## Logging: UPDATE
| Event ID | Event Name | Data Source | Log Provider |
|---------|---------|----------|----------|
| [1](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-1.md) | Process Access | Process Creation | Sysmon Event Logs | 


## Data Analytics: UPDATE
| Analytic Platform | Analytic Type  | Analytic Logic | Additional Information |
|--------|---------|---------|---------|
| Kibana | Rule | `Need to add` | Need to make a KSQL stream JOIN. 
| Splunk | Rule | ` Need to Add ` | None
| SparkSQL | Rule | `SELECT  b.process_path, b.process_target_name, b.process_target_id, b.thread_new_id, a.process_id, a.process_granted_access FROM sysmon_events b INNER JOIN( SELECT event_id, process_granted_access, process_guid, process_id FROM sysmon_events  WHERE event_id = 10 AND (process_granted_access & 5184) == 5184 -- 5184 is decimal for 0x1440. The minimal privileges you need to access process handle) a ON a.process_guid = b.process_guid WHERE b.event_id = 8`| Create a JOIN on the both event ID 8 and 10's SourceProcessGUID along with both event's TargetProcessGUID

# Techinical Context: UPDATE
Windows Transactional NTFS (TxF) allows for transactions to be integrated into the NTFS file system. 

Based off of this behavior, there are 2 APIs that correlate with 2 Sysmon events can be used for detection:

1. Sysmon Event ID 1 - Process Creation. This event will call the event registraion mechanism: `PsSetCreateProcessNotifyRoutine `, which is a kernel callback function inside of Windows. Inside of the Sysmon driver, the `NtCreateProcessEx` API is funneled through this event registration mechanism to create an ID of 1. 
The advesary needs to call NtCreateProcessEx to create a new process in a "fileless" way. 


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
* [Process Doppelgänging – a new way to impersonate a process](https://hshrzd.wordpress.com/2017/12/18/process-doppelganging-a-new-way-to-impersonate-a-process/)

