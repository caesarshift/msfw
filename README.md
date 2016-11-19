# Microsoft&reg; Firewall (msfw)

**Please note that this tool is not affiliated with or created by Microsoft Corporation.**

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

## Download

| Release                                                                               | MD5                               | SHA1                                     |
|---------------------------------------------------------------------------------------|-----------------------------------|------------------------------------------|
| [msfw v0.2](https://github.com/caesarshift/msfw/releases/download/v0.2/msfw-v0.2.zip) | e82d23ff59fc9ae9f1c9754338138914  | 685743552b8b032f6f091555b03c06ded65a8627 |
| [msfw v0.1](https://github.com/caesarshift/msfw/releases/download/v0.1/msfw-v0.1.zip) | 44dacb1099cefbc3450f4429e08f9838  | 77d1b2c7797b0b04904a2c8ae5a12974465cccb0 |

* On Windows, run `certutil -hashfile msfw-v0.2 MD5` OR `certutil -hashfile msfw-v0.2 SHA1` to calculate hashfile

## Getting Started

On Windows, a network connection is assigned a "profile": Domain, Private, or Public. The Microsoft firewall can be enabled/disabled for any or all profiles. Similarly, rules can be configured for any or all profiles.

```
> msfw -h
  status          Display firewall status.
  interface       Display included/excluded network interfaces.
  log             Display firewall log.
  rule            Display firewall rules.
  addrule         Add firewall rules.
  delrule         Delete firewall rules.
  updinterface    Update included/excluded interfaces.
  updlog          Enable/Disable firewall log.
  updstatus       Change firewall status.

> msfw status -h
  -p, --profile      (Default: ) Firewall profile.
  -i, --interface    (Default: False) List status by interface

> msfw interface -h
  -n, --interfacename    (Default: ) Interface Name

> msfw rule -h
  -l, --list        (Default: False) List out rules
  -c, --count       (Default: False) Count rules
  --scope           (Default: ) Include local and/or group policy rules
  --shortapp        (Default: False) Display executable name only in log output
  --string          (Default: False) Display rule as a string
  -p, --profile     (Default: ) Firewall profile.
  -n, --rulename    (Default: ) Rule Name
  --dir             (Default: ) Rule Direction [in, out]
  --status          (Default: enabled) Rule Status [enabled,disabled,all]
  --action          (Default: ) Rule Action [allow, block]
  --local           (Default: System.String[]) Rule Local Address and Ports
  --remote          (Default: System.String[]) Rule Remote Address and Ports
  --protocol        (Default: ) Rule Protocol
  --app             (Default: ) Rule Application or Service
  --ext             (Default: ) Rule Extended attributes
  
$ msfw log -h
  -s, --status    (Default: False) Display Status
  -l, --list      (Default: False) Display Blocked Connections
  -t, --tail      (Default: False) Tail Blocked Connections events
  --since         (Default: ) Filter by time since datetime string
  --last          (Default: ) Filter by time in last seconds, minutes, or hours
  --shortapp      (Default: False) Display executable name only in log output

> msfw addrule -h
  -p, --profile     (Default: ) Firewall profile.
  -n, --rulename    (Default: ) Rule Name. REQUIRED.
  --action          (Default: ) Rule Action [allow, block]. REQUIRED.
  --app             (Default: ) Rule Application or Service
  --dir             (Default: ) Rule Direction [in, out]. REQUIRED.
  --local           (Default: System.String[]) Rule Local Address and Ports
  --protocol        (Default: ) Rule Protocol
  --remote          (Default: System.String[]) Rule Remote Address and Ports
  --status          (Default: enabled) Rule Status [enabled,disabled,all]
  --scope           (Default: ) Include local and/or group policy rules

$ msfw delrule -h
  -n, --rulename        (Default: ) Rule Name
  --alllocaldisabled    (Default: False) Delete all local disabled rules

> msfw updinterface -h
  -p, --profile          (Default: ) Firewall profile.
  -n, --interfacename    (Default: ) Interface Name
  -e, --exclude          (Default: False) Exclude this interface
  -i, --include          (Default: False) Include this interface

$ msfw updlog -h
  -e, --enable     (Default: False) Enable log
  -d, --disable    (Default: False) Disable log  

> msfw updstatus -h
  -p, --profile     (Default: ) Firewall profile.
  -s, --status      (Default: ) TODO: Enabled/Disable Firewall [enable,disable]
  -i, --inbound     (Default: ) Set default inbound action [allow,block]
  -o, --outbound    (Default: ) Set default outbound action [allow,block]
```

## Configure Firewall
To see if your firewall is currently enabled, run the following:

### **```msfw status```**

Definition: Display firewall status information.

* "Enabled": Firewall is turned on
* "Disabled": Firewall is turned off
* "Active": Firewall is associated with a profile that has at least one active network connection
* "Inactive": Firewall is not associated with a profile that has an active network connection
* "Inbound": Default action [block,allow] for inbound traffic
* "Outbound": Default action [block,allow] for outbound traffic
* "Interface": Network adapter name
* "Network": Network name
* "Excluded": If interface is excluded from the firewall

Syntax: **`msfw status -p [domain|private|public] [-i]`**

Example:
```
> msfw status
"Profile","Status","Active","Inbound","Outbound"
"Domain","Enabled","Active","Allow","Allow"
"Private","Enabled","Active","Allow","Allow"
"Public","Enabled","Inactive","Block","Allow"
```

Example by profile:
```
> msfw status -p domain
"Profile","Status","Active","Inbound","Outbound"
"Domain","Enabled","Active","Allow","Allow"
```

Example by interface (Inactive profiles will have blank interface names):
```
> msfw status -i
"Profile","Status","Active","Inbound","Outbound","Interface","Network","Excluded"
"Domain","Enabled","Inactive","Allow","Allow","","",""
"Private","Enabled","Active","Allow","Allow","Wireless Network Connection","myhomenetwork","Included"
"Public","Enabled","Inactive","Block","Allow","","",""
```

### **```msfw interface```**

Definition: Display list of interfaces.

NOTE: Firewall Profiles <-> interfaces <-> networks. Most networks will only be connected to one interface, but it's possible to have 2 (or more) interfaces for 1 network. In that case, you must exclude both interfaces in order to exclude the network. 

Syntax: **`msfw interface -n <interfacename>`**

Example:
```
> msfw interface
"Interface","Domain","Private","Public"
"Wireless Network Connection","Included","Included","Included"
"Local Area Connection","Excluded","Included","Included"
"VMware Network Adapter VMnet1","Included","Included","Included"
"Loopback Pseudo-Interface 1","Included","Included","Included"
```
Example by interface name:
```
> msfw interface -n "local area connection"
"Interface","Domain","Private","Public"
"Local Area Connection","Excluded","Included","Included"
```

### **```msfw log```**  **(Requires admin privileges)**

Displays the "Filtering Platform Packet Drop" auditing of failures. The built-in firewall logging is not used as it does not display the application/service name associated with a blocked packet. The drawback is that log filtering cannot be scoped to a specific profile.

#### ```msfw log --status``` **(Requires admin privileges)**

Definition: Display firewall log status.

Syntax: **`msfw log [-s,--status]`**

Example:
```
$ msfw log
Logging Enabled: True
```

#### ```msfw log --list``` **(Requires admin privileges)**

Definition: List firewall blocked records.

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

#### ```msfw log -t``` **(Requires admin privileges)**

Definition: Tail firewall log

Syntax: **`msfw log -t`**

### **```msfw updlog```**  **(Requires admin privileges)**

Updates the log configuration.

#### ```msfw updlog --enable``` **(Requires admin privileges)**

Definition: Enable firewall logging.

Syntax: **`msfw log [-e,--enable]`**

Example:
```
> msfw updlog -e
Action: Enable log (requires admin privileges)
The command was successfully executed.
```

#### ```msfw updlog --disable``` **(Requires admin privileges)**

Definition: Disable firewall logging.

Syntax: **`msfw log [-d,--disable]`**

Example:
```
> msfw updlog -d
Action: Disable log (requires admin privileges)
The command was successfully executed.
```

## Configure Rules

Firewall rules can be created locally or pushed down via group policy. Rules can also be disabled/enabled.

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

### ```msfw addrule```

Create firewall rules

#### ```msfw addrule -n <rulename> --dir [in,out] --action [allow,block]```

Definition: Create a rule. Minimum required fields: rule name, direction, and action. Note that names do not have to be unique, but from a best practices perspective, it's a good idea to do so.

Syntax: **`msfw addrule -n <rulename> --dir [in,out] --action [allow,block]`**

Default: `--local *:* --remote *:* --protocol * --application * --profile *`

Example: Create a rule blocking all inbound traffic
```
> msfw addrule -n "Hello, World" --dir in --action block
Added rule: Hello World
```

Example: Create a rule blocking all inbound traffic to port 443
```
> > msfw addrule -n "Hello, World" --dir in --action block --local 443
Added rule: Hello World
```

Example: Create a rule blocking all inbound traffic to port 443 (alternate)
```
> > msfw addrule -n "Hello, World" --dir in --action block --local *:443
Added rule: Hello World
```

Example: Create a rule blocking all inbound traffic to IP 1.1.1.1 on ports 80 and 443
```
> > msfw addrule -n "Hello, World" --dir in --action block --local 1.1.1.1 80 443
Added rule: Hello World
```

Example: Create a rule blocking all inbound traffic to IP 1.1.1.1 on ports 80 and 443 (alternate)
```
> > msfw addrule -n "Hello, World" --dir in --action block --local 1.1.1.1:80 1.1.1.1:443
Added rule: Hello World
```

### ```msfw delrule```

Delete firewall rules.

#### ```msfw delrule -n <rulename>```

Definition: Delete a rule. Minimum required fields: rule name

Syntax: **`msfw delrule -n <rulename>`**

Default: None

Example: Delete all rules named "Hello, World"

```
> msfw delrule -n "Hello, World"
Deleted 3 rule(s).
```

### ```msfw updinterface```

Include or exclude interfaces from firewall.

#### ```msfw updinterface -n <interfacename> [--include|--exclude] [-p domain|private|public]```

Definition: Include or exclude an interface. Minimum required fields: rule name and action

Syntax: **`msfw updinterface -n <interfacename> [--include|--exclude] [-p domain|private|public]`**

Default: All profiles.

Example: Exclude interface from all profiles

```
> msfw updinterface -n "local area connection" --exclude
```

Example: Exclude interface from domain profile

```
> msfw updinterface -n "local area connection" -p domain --exclude
```

Example: Include interface on all profiles

```
> msfw updinterface -n "local area connection" --include
```

### ```msfw updstatus```

Enable/Disable firewall or change inbound/outbound default actions.

Example: Change default inbound action for the public profile to block
```
> msfw updstatus -p public -i block
```

Example: Change default outbound action for the public profile to block
```
> msfw updstatus -p public -i block
```

## Version history
* **0.1** (2016-10-09) - Initial release. Release of msfw binary with status, rule, and log subcommands.
* **0.2** (2016-10-24) - Bug fixes. Release of msfw binary with log -t (tail log), status -i (by interface), interface, updinterface, addrule, and delrule. Reformatted status output.
* **0.3** (2016-11-XX) - Release of msfw binary with reformat of status command and display network connections
* **0.4** (2016-11-XX) - Bug fixes.
* **0.5** (2016-12-XX) - Release of msfw binary with status change and log change subcommands.
* **0.6** (2016-12-XX) - Bug fixes.
* **1.0** (2017-01-01) - Release of code and msfw binary with rule creation subcommands.

## License

msfw is licensed under the [MIT](http://www.opensource.org/licenses/mit-license.php).

## Other libraries used by msfw

* [CommandLineParser](https://github.com/gsscoder/commandline) *(MIT License)*
* [NLog](https://github.com/NLog/NLog) *(BSD-3-License)*
