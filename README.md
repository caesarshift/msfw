# Microsoft&reg; Firewall (msfw)

**Please note that this tool is not affiliated with, created by, or associated with Microsoft Corporation.**

*Microsoft, Encarta, MSN, and Windows are either registered trademarks or trademarks of Microsoft Corporation in the United States and/or other countries.*

## Goal: Provide a simple solution to using the Windows Firewall

## Requirements

* Windows 7 or newer with .NET 3.5+
* For some functions, administrative access is required

## Getting Started

On Windows, a network connection is assigned a "profile": Domain, Private, or Public. The Microsoft firewall can be enabled/disabled for any or all profiles. Similarly, rules can be configured for any or all profiles.

```
> msfw -h
msfw 0.1

  -p, --profile     (Default: ) Firewall profile.
  -l, --list        (Default: False) List out rules
  -c, --count       (Default: False) Count rules
  --local-rules     (Default: False) Only include local rules
  --policy-rules    (Default: False) Only include local rules
  -n, --rulename    (Default: ) Rule Name
  --dir             (Default: ) Rule Direction [in, out]
  --status          (Default: enabled) Rule Status [enabled,disabled,all]
  --action          (Default: ) Rule Action [allow, block]
  --local           (Default: System.String[]) Rule Local Address and Ports
  --remote          (Default: System.String[]) Rule Remote Address and Ports
  --protocol        (Default: ) Rule Protocol
  --app             (Default: ) Rule Application or Service
  --help            Display this help screen.
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
* **0.1** (2016-10-08) - Initial release. Documentation of status and rule subcommands.
* **0.2** (2016-10-XX) - Documentation of log subcommands.
* **0.3** (2016-11-XX) - Release of msfw binary with status, rule, and log subcommands.
* **0.4** (2016-11-XX) - Bug fixes.
* **0.5** (2016-12-XX) - Release of msfw binary with status change and log change subcommands.
* **0.6** (2016-12-XX) - Bug fixes.
* **1.0** (2017-01-01) - Release of code and msfw binary with rule creation subcommands.

## License

msfw is licensed under the [MIT](http://www.opensource.org/licenses/mit-license.php).

## Other libraries used by msfw

[CommandLineParser](https://github.com/gsscoder/commandline) *(MIT License)*