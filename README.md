# Microsoft&reg; Firewall (msfw)

**Please note that this tool is not affiliated with, created by, or associated with Microsoft Corporation.**

*Microsoft, Encarta, MSN, and Windows are either registered trademarks or trademarks of Microsoft Corporation in the United States and/or other countries.*

## Goal: Provide a simple command line interface to the built-in Windows Firewall

## Why

1. No complete command line solution for configuring or monitoring the Windows firewall
  * "netsh advfirewall" solution does not list rule results in a tabular format
  * "netsh advfirewall" does not work with group policy
    * If group policy enables firewall, "netsh" does not show firewall as running
    * If group policy pushes down rules, "netsh" does not show those rules
  * Missing search features ("find rules with any/any local ports and any/any remote ports" criteria)
1. Incomplete Logging features
  * Built-in firewall logging is disabled by default
  * Built-in firewall logging does not show executable associated with a blocked packet
  * No command line access to logs in a reasonable format

## Requirements

* Windows 7 or newer with .NET 3.5+
* For some functions, administrative privileges are required

## Getting Started

On Windows, a network connection is assigned a "profile": Domain, Private, or Public. The Microsoft firewall can be enabled/disabled for any or all profiles. Similarly, rules can be configured for any or all profiles.

```
> msfw
  status    Display firewall status.
  rule      Display firewall rules.
  log       Display firewall log.

> msfw status -h
  -p, --profile    (Default: ) Firewall profile.
  
> msfw rule -h
msfw 0.1
  -l, --list        (Default: False) List out rules
  -c, --count       (Default: False) Count rules
  -p, --profile     (Default: ) Firewall profile.
  -n, --rulename    (Default: ) Rule Name
  --action          (Default: ) Rule Action [allow, block]
  --app             (Default: ) Rule Application or Service
  --dir             (Default: ) Rule Direction [in, out]
  --local           (Default: System.String[]) Rule Local Address and Ports
  --protocol        (Default: ) Rule Protocol
  --remote          (Default: System.String[]) Rule Remote Address and Ports
  --status          (Default: enabled) Rule Status [enabled,disabled,all]
  --scope           (Default: ) Include local and/or group policy rules
  
> msfw log -h
  -e, --enable     (Default: False) Enable log
  -d, --disable    (Default: False) Disable log
  -s, --status     (Default: False) Display Status
  -l, --list       (Default: False) Display Blocked Connections
  --since          (Default: ) Filter by time since datetime string
  --last           (Default: ) Filter by time in last seconds, minutes, or
                   hours
  --shortapp       (Default: False) Display executable name only in log output
```

## Configure Firewall
To see if your firewall is currently enabled, run the following:

### **```msfw status```**

**`msfw status`** : Display firewall status information

```
> msfw status
'Windows Firewall' Service: Running
Domain: Enabled:Inactive
Private: Enabled:Active
Public: Enabled:Inactive
```

* "Enabled": Firewall is turned on
* "Disabled": Firewall is turned off
* "Active": Firewall is associated with a profile that has at least one active network connection
* "Inactive": Firewall is not associated with a profile that has an active network connection

**`msfw status -p [domain|private|public]`** : Display firewall status information for a profile

```
> msfw status -p private
Private: Enabled:Active
```

### **```msfw log```**  **(Requires admin privileges)**

Displays the "Filtering Platform Packet Drop" auditing of failures. The built-in firewall logging is not used as it does not display the application/service name associated with a blocked packet. The drawback is that filtering cannot be enabled for a specific profile.

#### ```msfw log --status``` **(Requires admin privileges)**

Definition: Display firewall log status.

Syntax: **`msfw log [-s,--status]`**

Example:
```
> msfw log -s
Filter logging: True
```

#### ```msfw log --enable``` **(Requires admin privileges)**

Definition: Enable firewall logging.

Syntax: **`msfw log [-e,--enable]`**

Example:
```
> msfw log -e
Action: Enable log (requires admin privileges)
The command was successfully executed.
```

#### ```msfw log --disable``` **(Requires admin privileges)**

Definition: Disable firewall logging.

Syntax: **`msfw log [-d,--disable]`**

Example:
```
> msfw log -d
Action: Disable log (requires admin privileges)
The command was successfully executed.
```

#### ```msfw log --list``` **(Requires admin privileges)**

Definition: List firewall logs.

Syntax: **`msfw log [-l,--list]`**

Example:
```
> msfw log -l
Retrieving Logs since: 2016-10-09 14:30:43
Retrieving Logs since (UTC): 2016-10-09 19:30:43
10/9/2016 2:31:06 PM \device\harddiskvolume1\program files (x86)\landesk\ldclient\issuser.exe Out 10.10.10.10 42801 5.5.5.5 443 Tcp
10/9/2016 2:31:08 PM \device\harddiskvolume1\windows\system32\svchost.exe In 0.0.0.0 68 255.255.255.255 67 Udp
```

#### ```msfw log --l --shortapp``` **(Requires admin privileges)**

Definition: List application name only (not full path)

Syntax: **`msfw log -l [--shortapp]`**

Example:
```
> msfw log -l --shortapp
Retrieving Logs since: 2016-10-09 14:30:43
Retrieving Logs since (UTC): 2016-10-09 19:30:43
10/9/2016 2:31:06 PM issuser.exe Out 10.10.10.10 42801 5.5.5.5 443 Tcp
10/9/2016 2:31:08 PM svchost.exe In 0.0.0.0 68 255.255.255.255 67 Udp
```

#### ```msfw log -l --since``` **(Requires admin privileges)**

Definition: List firewall logs since datetime

Syntax: **`msfw log -l [--since <datetimestring>]`**

Example:
```
> msfw log -l --since "2016-10-10 12:00:00 PM"
```

Example:
```
> msfw log -l --since "2016-10-10 14:00:00 PM"
```

#### ```msfw log -l --last``` **(Requires admin privileges)**

Definition: List firewall logs in last hours, minutes, or seconds

Syntax: **`msfw log -l [--last <duration>]`**


Example:
```
> msfw log -l --last 5m
```

Example:
```
> msfw log -l --last 30s
```

## Configure Rules

Rules, additionally, can be created locally or pushed down via group policy. Rules can also be disabled/enabled.

### ```msfw rule```

List rule details or count the number of rules found

* Use `-l` to see a list of rules
* Use `-c` to see a count of rules

#### ```msfw rule --status```

Definition: List rules by status.

Syntax: **`msfw rule -l --status [enabled,disabled,all]`**

Default: `--status enabled`

Example: List enabled rules
```
> msfw rule -l
"Profile","Action","Direction","Application","Local","Remote","Protocol","Name"
"--,Pr,--","Allow","Out","System","*:*","LocalSubnet:138","Udp","Network Discovery (NB-Datagram-Out)"
"--,Pr,--","Allow","In","System","*:138","LocalSubnet:*","Udp","Network Discovery (NB-Datagram-In)"
"Do,Pr,Pu","Allow","Out","%SystemRoot%\system32\svchost.exe:dnscache","*:*","*:53","Udp","Core Networking - DNS (UDP-Out)"
"Do,--,--","Allow","Out","System","*:*","*:445","Tcp","Core Networking - Group Policy (NP-Out)"
"Do,Pr,Pu","Allow","In","System","*:*","*:*","IPv6","Core Networking - IPv6 (IPv6-In)"
```

Example: Count all rules
```
> msfw rule -c --status all
Rule count: 219
```

#### ```msfw rule [-p,--profile] <profile>```

Defintion: List rules by profile

Syntax: **`msfw rule -l -p [{domain|private|public|all}]`**

Default: `-p all`

Example: List enabled, private profile rules
```
> msfw rule -l -p private
"Profile","Action","Direction","Application","Local","Remote","Protocol","Name"
"--,Pr,--","Allow","Out","System","*:*","LocalSubnet:138","Udp","Network Discovery (NB-Datagram-Out)"
"Do,Pr,Pu","Allow","In","System","*:*","*:*","IPv6","Core Networking - IPv6 (IPv6-In)"
[snip]
```

#### ```msfw rule --action```

Defintion: List rules by action.

Syntax: **`msfw rule -l --action [{allow,block}]`**

Default: Both

Example: List enabled, allow rules
```
> msfw rule -l --action allow
```

Example: List enabled, block rules
```
> msfw rule -l --action block
```

#### ```msfw rule --rulename```

Defintion: List rule by name (case insensitive full string match)

Syntax: **`msfw rule -l [-n|--rulename] <rulename>`**

Default: None

Example: List enabled rule with name "Rule Name"
```
> msfw rule -l -n "Rule Name"
```

#### ```msfw rule --dir```

Defintion: List rule by direction

Syntax: **`msfw rule -l [--dir [{in,out}]`**

Default: Both

Example: List enabled, inbound rules
```
> msfw rule -l --dir in"
```

Example: List enabled, outbound rules
```
> msfw rule -l --dir out"
```

#### ```msfw rule --local```

Defintion: List rules by local ports and addresses

Syntax: **`msfw rule -l --local <address>:<port>`**

Default: All

Example: List enabled, any:any local address/port rule
```
> msfw rule -l --local *:*
```

Example: List enabled, inbound, allow rules with any:any local address/port
```
> msfw rule -l --local *:* --dir in --action allow
```

Example: List enabled, inbound, allow rules with single IP and any port
```
> msfw rule -l --local 10.10.10.10:* --dir in --action allow
```

Example: List enabled, inbound, allow rules with any local IP but a single port
```
> msfw rule -l --local *:443 --dir in --action allow
```

#### ```msfw rule --remote```

Defintion: List rules by remote ports and addresses

Syntax: **`msfw rule -l --remote <address>:<port>`**

Default: All

Example: List enabled, any:any remote address/port rule
```
> msfw rule -l --remote *:*
```

Example: List enabled inbound, allow rules with any:any remote address/ports
```
> msfw rule -l --remote *:* --dir in --action allow
```

Example: List enabled inbound, allow rule with any/any local AND any/any remote addresses/ports
```
> msfw rule -l --local *:* --remote *:* --dir in --action allow
```

Example: List enabled inbound, allow rule with any/any local AND any/any remote addresses/ports
```
> msfw rule -l --local *:* --remote *:* --dir in --action allow
```

#### ```msfw rule --protocol```

Defintion: List rules by protocol

Syntax: **`msfw rule -l --protocol <protocol>`**

Default: All

Example: List enabled, tcp rules
```
> msfw rule -l --protocol tcp
```

Example: List enabled, icmp rules
```
> msfw rule -l --protocol icmp
```

#### ```msfw rule --app```

Defintion: List rules by application (or service). Base filename is used for case insensitive full string match

Syntax: **`msfw rule -l --app <name>`**

Default: All

Example: List enabled, Windows service rules
```
> msfw rule -l --app svchost.exe
```

Example: List enabled, "java.exe" rules
```
> msfw rule -l --app java.exe
```

Example: List enabled, Windows service rules
```
> msfw rule -l --app svchost.exe
```

Example: List enabled, Windows service uPnP rules
```
> msfw rule -l --app upnphost
```

#### ```Common msfw rules```

Example: List enabled allow rules with any/any local AND any/any remote addresses/ports AND any application
```
> msfw rule -l --local *:* --remote *:* --dir in --app * --action allow
```

#### ```msfw rule --scope```

Defintion: List rules by scope (local and/or group policy)

Syntax: **`msfw rule -l --scope [{local,policy}]`**

Default: All

Example: List enabled, local rules
```
> msfw rule -l --scope local
```

Example: List enabled, group policy rules
```
> msfw rule -l --scope policy
```

## Version history
* **0.1** (2016-10-09) - Initial release. Release of msfw binary with status, rule, and log subcommands.
* **0.2** (2016-10-XX) - Bug fixes.
* **0.3** (2016-11-XX) - Release of msfw binary with reformat of status command and display network connections
* **0.4** (2016-11-XX) - Bug fixes.
* **0.5** (2016-12-XX) - Release of msfw binary with status change and log change subcommands.
* **0.6** (2016-12-XX) - Bug fixes.
* **1.0** (2017-01-01) - Release of code and msfw binary with rule creation subcommands.

## License

msfw is licensed under the [MIT](http://www.opensource.org/licenses/mit-license.php).

## Other libraries used by msfw

[CommandLineParser](https://github.com/gsscoder/commandline) *(MIT License)*