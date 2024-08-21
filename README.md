# AnomalyFinder-AI
AnomalyFinder-AI is an AI tool for detecting and analyzing anomalies in log data from various systems and applications. It identifies irregular patterns, provides descriptions of anomalies, and suggests solutions to prevent issues. 

## =================SYSTEM ANOMALIES===================

## Authentication and Access

- **Failed Login Attempts**: Excessive failed login attempts from a single user or IP address.
- **Successful Logins from Unusual Locations**: Logins from geographic locations or IP addresses not typical for the user.
- **Login Attempts with Disabled Accounts**: Attempts to log in using disabled or expired user accounts.
- **Multiple Concurrent Logins**: Multiple simultaneous logins from the same account.
- **Successful Logins Outside Normal Hours**: Logins occurring at unusual times.
- **Unexpected Privilege Escalation**: Users obtaining administrative or higher privileges unexpectedly.
- **Account Lockout Events**: Frequent account lockouts due to multiple failed login attempts.
- **Disabled Account Logins**: Logins or access attempts using disabled accounts.
- **High Number of Account Changes**: Frequent changes in user account properties or permissions.
- **Unexpected Password Changes**: Changes in user passwords that are not initiated by the user.


## System and Application Errors

- **Frequent System Reboots**: Unscheduled or frequent system reboots.
- **Application Crashes**: High frequency of application crashes or unexpected terminations.
- **Service Failures**: Repeated failures of critical services or system components.
- **Blue Screen of Death (BSOD)**: Unplanned system crashes resulting in BSOD errors.
- **Event Log Corruption**: Errors indicating corruption or issues with the event log itself.
- **High System Resource Usage**: Unusual spikes in CPU, memory, or disk usage.
- **Unexpected System Shutdowns**: Abrupt or unexpected system shutdowns.
- **Driver Failures**: Frequent failures of hardware drivers or device malfunctions.
- **Unusual Error Codes**: Uncommon or unexpected error codes in system logs.
- **Unhandled Exceptions**: Frequent unhandled exceptions in applications.


## Security Events

- **Malware Detection Alerts**: Alerts from antivirus or security software about detected malware.
- **Unauthorized Access to Sensitive Files**: Access attempts to sensitive or restricted files.
- **Suspicious PowerShell Commands**: Execution of unusual or potentially harmful PowerShell commands.
- **File Integrity Changes**: Unexpected changes to critical system or application files.
- **Unusual Network Connections**: Connections to unknown or unauthorized network addresses.
- **Unauthorized Administrative Actions**: Administrative actions performed by non-administrative users.
- **Event Log Clearing**: Unusual clearing or modification of event log entries.
- **Failed Antivirus Scans**: Repeated failures of antivirus or security scans.
- **Network Intrusion Attempts**: Detected attempts to exploit vulnerabilities in the network.
- **Unusual Port Scanning**: Detection of port scanning activities from unfamiliar sources.


## Configuration Changes

- **Unexpected Changes in Security Policies**: Modifications to security policies or settings without authorization.
- **Alterations to Group Policies**: Unexpected changes to group policy settings.
- **Configuration File Changes**: Unusual changes in configuration files for critical applications or services.
- **Unplanned Software Installations**: Unauthorized or unplanned installations of software.
- **Changes in System Services**: Modifications to critical system services or their configurations.
- **Group Membership Changes**: Unexpected changes in user group memberships.
- **Registry Changes**: Unauthorized modifications to the Windows Registry.
- **Changes in Scheduled Tasks**: Creation or modification of scheduled tasks that were not planned.
- **Firewall Rule Changes**: Unplanned changes in firewall rules or configurations.
- **Unexpected Software Uninstallations**: Removal of important or critical software applications.


## Performance and Resource Issues

- **Memory Leaks**: Indications of memory leaks or excessive memory usage by applications.
- **Disk Space Exhaustion**: Low or critically low disk space on system drives.
- **High Disk I/O**: Unusual or excessive disk input/output operations.
- **Slow System Performance**: General system performance degradation or slowness.
- **Application Startup Delays**: Unusual delays in application startup times.
- **Network Latency Spikes**: Increased network latency or connectivity issues.
- **High Network Traffic**: Unusual spikes in network traffic volumes.
- **Failed Backup Operations**: Repeated failures in backup operations or services.
- **Service Delays**: Delays in starting or stopping critical services.
- **Unusual CPU Usage**: High or fluctuating CPU usage by processes or services.


## User and Group Activities

- **Unusual User Behavior**: Unusual or abnormal user activities compared to baseline behavior.
- **Unexpected User Account Creation**: Creation of new user accounts without proper authorization.
- **Group Policy Application Failures**: Failures in applying or enforcing group policies.
- **Abnormal User Logout**: Frequent or unexpected user logouts or session terminations.
- **Multiple Failed Access Attempts**: Numerous failed attempts to access restricted areas.
- **User Account Enumeration**: Attempts to enumerate or discover valid user accounts.
- **Suspicious Remote Access**: Remote access attempts from unfamiliar or untrusted sources.
- **Unusual User Privilege Assignments**: Assignments of elevated privileges or permissions to users.
- **High Volume of Login Attempts**: Excessive login attempts from a single user or IP.
- **Unexpected User Profile Changes**: Unplanned changes to user profiles or settings.


## Network and Connectivity

- **Failed Network Connections**: Failed or refused network connection attempts.
- **Unusual Outbound Connections**: Unexpected outbound network connections to unknown destinations.
- **IP Address Changes**: Frequent or unexpected changes in IP address assignments.
- **DNS Resolution Failures**: Failures in resolving DNS queries or unusual DNS requests.
- **Suspicious Network Protocols**: Detection of unusual or unauthorized network protocols.
- **Network Configuration Changes**: Unauthorized changes in network configuration settings.
- **Network Interface Errors**: Errors related to network interface cards or connections.
- **Suspicious Traffic Patterns**: Detection of abnormal traffic patterns that deviate from normal.
- **Intrusion Detection System (IDS) Alerts**: Alerts from IDS about potential network intrusions.
- **Unusual VPN Connections**: Connections to VPNs that are not typically used or expected.


## System Integrity

- **Unauthorized File Changes**: Changes to system or application files without authorization.
- **System Integrity Check Failures**: Failures in system integrity checks or file verification processes.
- **Missing Critical Files**: Detection of missing or deleted critical system files.
- **Unexpected System File Modifications**: Modifications to system files that are not part of regular updates or maintenance.
- **Unauthorized Software Execution**: Execution of unauthorized or unapproved software applications.
- **Changes in System Configuration Files**: Unauthorized changes to system configuration files.
- **Unverified Software Installations**: Installation of software from untrusted sources.
- **Corrupted System Files**: Detection of corruption in critical system files.
- **Unexpected Kernel Mode Changes**: Changes in kernel mode or low-level system components.
- **Integrity Violations**: Violations of file or system integrity checks.


## Other Potential Anomalies

- **Unusual Event Log Size Increases**: Unexpected increases in the size of event logs.
- **High Number of Failed Service Starts**: A high number of failed attempts to start critical services.
- **Unexpected Service Restarts**: Frequent or unexpected restarts of important system services.
- **Unplanned Device Changes**: Detection of unexpected changes in hardware or device configurations.
- **Anomalous System Time Changes**: Changes in system time that do not align with expected patterns.
- **Failed Device Drivers**: Errors or failures related to device drivers.
- **Unexpected System Parameter Changes**: Modifications to system parameters or settings that are not part of regular updates.
- **Unusual Event Types**: Detection of event types that are not commonly recorded in the logs.
- **High Frequency of Security Events**: Increased frequency of security-related events such as failed logins or access denials.
- **Unexpected System Configuration Drift**: Changes in system configuration that deviate from known baselines or expected configurations.

