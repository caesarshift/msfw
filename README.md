# Microsoft&reg; Firewall (msfw)

**Please note that this tool is not affiliated with, created by, or associated with Microsoft Corporation.**

*Microsoft, Encarta, MSN, and Windows are either registered trademarks or trademarks of Microsoft Corporation in the United States and/or other countries.*

## Goal: Provide a simple solution to using the Windows Firewall

## Requirements

* Windows 7 or newer with .NET 3.5+
* For some functions, administrative access is required

## Getting Started

On Windows, a network connection is assigned a "profile": Domain, Private, or Public. The Microsoft firewall can be enabled/disabled for any or all profiles. Similarly, rules can be configured for any or all profiles.

```> msfw -h
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
  --help            Display this help screen.```

## Configure Firewall
To see if your firewall is currently enabled, run the following:

```msfw status```

If you see "Enabled", then your firewall is turned on.

If you see "Inactive", then you do not currently have any networks connected to the given profile.

To check a particular domain, just add the "profile" name:

```msfw status -p private```

## Configure Rules

Rules, additionally, can be created locally or pushed down via group policy. Rules can also be disabled/enabled.

By default, msfw will not display disabled rules in the list. If you want to include disabled rules, then include the following flag:

List all rules

```msfw rule -l --status all```

List enabled rules

```msfw rule -l```

List disabled rules

```msfw rule -l --status all```

List <profile> rules

```msfw rule -l -p private```

List local (not group policy) rules:

```msfw rule -l --local-rules```

List group policy rules:

```msfw rule -l --policy-rules```

List rule <name> (case insensitive):

```msfw rule -l -n "Rule Name"```

List inbound rules

```msfw rule -l --dir in```

List outbound rules

```msfw rule -l --dir out```

List allow rules

```msfw rule -l --action allow```

List block rules

```msfw rule -l --action block```

List allow rules with any:any local address/ports

```msfw rule -l --local *:* --dir in --action allow```

List allow rules with any:any local address/ports

```msfw rule -l --local *:* --dir in --action allow```

List inbound, allow rules with any:any remote address/ports

```msfw rule -l --remote *:* --dir in --action allow```

List inbound, allow rules with a local IP and any port

```msfw rule -l --local 10.10.10.10:* --dir in --action allow```

List inbound, allow rules with any local IP but a single port

```msfw rule -l --local *:443 --dir in --action allow```

List inbound, allow rule with any/any local AND any/any remote addresses/ports

```msfw rule -l --local *:* --remote *:* --dir in --action allow```

List allow rules with any/any local AND any/any remote addresses/ports AND any application

```msfw rule -l --local *:* --remote *:* --dir in --app * --action allow```

List windows service rules

```msfw rule -l --app svchost.exe```

List windows <service>

```msfw rule -l --app upnphost```

List TCP protocol rules

```msfw rule -l --protocol tcp```

List ICMP protocol rules

```msfw rule -l --protocol icmp```

## Version history
* 0.1 2016-10-08 Initial release. Documentation of status and rule subcommands
* 0.2 2016-10-XX Documentation of log subcommands
* 0.3 2016-11-XX Release of msfw binary with status, rule, and log subcommands
* 0.4 2016-11-XX Bug fixes
* 0.5 2016-11-XX Bug fixes
* 0.6 2016-12-XX Release of msfw binary with rule creation subcommands
* 1.0 2017-01-01 Release of code and msfw binary with rule creation subcommands

## License

msfw is licensed under MIT.

## Other libraries

[CommandLineParser](https://github.com/gsscoder/commandline)