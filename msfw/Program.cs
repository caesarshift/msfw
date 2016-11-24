using System;                         //default
using System.Collections.Generic;     //lists
using NetFwTypeLib;                   //c# firewall class
using msfw;                           //msfw class
using CommandLine;                    //cli parsing
using CommandLine.Text;               //cli parsing
using System.Linq;                    //because Jon Skeet
using System.IO;                      //file name path
using System.Text.RegularExpressions; //date time parsing
using System.Net.Sockets;             //protocol enum

/*
 * TODOs
 * find duplicate rule
 * anonmyze test ips
 * add rule interactively (?)
 * add rule app from log (?)
 * msfw status --columns
 * msfw rule --columns
 * msfw ruleext --columns
 * msfw log --columns
 * msfw updstatus [--inbound,--outbound,--status] [enable,disable]
 * msfw updrule
 */
//todo: add block all for profile
//todo: report if block all for profile is present
//todo: option to consolidate same rules with different profiles
//todo: delete rules with same name (how to handle?)
//todo: find similar rules using gethashcode
//todo: allow change inbound and outbound
//todo: allow change active at policy level?
//todo: allow disable/enable rules by group
//todo: -n and regex across options
//todo: changes to program hash since rule?
//todo: changes to rules
//--columns "+colname,-colname, +colname"
namespace msfw
{
    enum ActionType
    {
        a,
        allow,
        b,
        block
    }

    //warning: since commandline does not support enums as array values,
    //the addrule verb uses strings to match. If you change this enum,
    //you must update addrule too.
    //pull request: https://github.com/gsscoder/commandline/pull/148
    enum ProfileType
    {
        @do,
        domain,
        pr,
        @private,
        pu,
        @public,
        al,
        all
    }

    enum StatusType
    {
        e,
        enable,
        d,
        disable
    }

    enum DirectionType
    {
        i,
        @in,
        o,
        @out
    }

    class UpdInterfaceSubOptions
    {
        [Option('p', "profile", DefaultValue = null,
        HelpText = "Firewall profile.")]
        public ProfileType? Profile { get; set; }

        [Option('n', "interfacename", DefaultValue = "",
        HelpText = "Interface Name")]
        public string IntName { get; set; }

        [Option('e', "exclude", DefaultValue = false,
        HelpText = "Exclude this interface", MutuallyExclusiveSet = "intaction")]
        public bool ActionExclude { get; set; }

        [Option('i', "include", DefaultValue = false,
        HelpText = "Include this interface", MutuallyExclusiveSet = "intaction")]
        public bool ActionInclude { get; set; }
    }

    class InterfaceSubOptions
    {
        [Option('n', "interfacename", DefaultValue = "",
        HelpText = "Interface Name")]
        public string IntName { get; set; }
    }

    class UpdStatusSubOptions
    {
        [Option('p', "profile", DefaultValue = null,
        HelpText = "Firewall profile.")]
        public ProfileType? Profile { get; set; }
        
        [Option('s', "status", DefaultValue = null,
        HelpText = "TODO: Enabled/Disable Firewall [enable,disable]")]
        public StatusType? Status { get; set; }
        
        [Option('i', "inbound", DefaultValue = null,
        HelpText = "Set default inbound action [allow,block]")]
        public ActionType? Inbound { get; set; }

        [Option('o', "outbound", DefaultValue = null,
        HelpText = "Set default outbound action [allow,block]")]
        public ActionType? Outbound { get; set; }
    }

    class RuleSharedOptions
    {
        [Option('p', "profile", DefaultValue = null,
        HelpText = "Firewall profile.")]
        public ProfileType? Profile { get; set; }

        [Option('n', "rulename", DefaultValue = "",
        HelpText = "Rule Name")]
        public string RuleName { get; set; }

        [Option("dir", DefaultValue = null,
        HelpText = "Rule Direction [in, out]")]
        public DirectionType? RuleDirection { get; set; }

        [Option("status", DefaultValue = "enabled",
        HelpText = "Rule Status [enabled,disabled,all]")]
        public string RuleStatus { get; set; }

        [Option("action", DefaultValue = "",
        HelpText = "Rule Action [allow, block]")]
        public string RuleAction { get; set; }

        [OptionArray("local", DefaultValue = new string[] { "" },
        HelpText = "Rule Local Address and Ports")]
        public string[] RuleLocal { get; set; }

        [OptionArray("remote", DefaultValue = new string[] { "" },
        HelpText = "Rule Remote Address and Ports")]
        public string[] RuleRemote { get; set; }

        [Option("protocol", DefaultValue = "",
        HelpText = "Rule Protocol")]
        public string RuleProtocol { get; set; }

        [Option("app", DefaultValue = "",
        HelpText = "Rule Application or Service")]
        public string RuleAppOrService { get; set; }

        [Option("ext", DefaultValue = "",
        HelpText = "Rule Extended attributes")]
        public string RuleExtended { get; set; }
    }

    class AddRuleSubOptions
    {
        [OptionArray('p', "profile", DefaultValue = new string[] { },
        HelpText = "Firewall profile.")]
        public string[] Profile { get; set; }

        [Option('n', "rulename", DefaultValue = "",
        HelpText = "Rule Name")]
        public string RuleName { get; set; }

        [Option("dir", DefaultValue = null,
        HelpText = "Rule Direction [in, out]")]
        public DirectionType? RuleDirection { get; set; }

        [Option("status", DefaultValue = "enabled",
        HelpText = "Rule Status [enabled,disabled,all]")]
        public string RuleStatus { get; set; }

        [Option("action", DefaultValue = "",
        HelpText = "Rule Action [allow, block]")]
        public string RuleAction { get; set; }

        [OptionArray("local", DefaultValue = new string[] { "" },
        HelpText = "Rule Local Address and Ports")]
        public string[] RuleLocal { get; set; }

        [OptionArray("remote", DefaultValue = new string[] { "" },
        HelpText = "Rule Remote Address and Ports")]
        public string[] RuleRemote { get; set; }

        [Option("protocol", DefaultValue = "",
        HelpText = "Rule Protocol")]
        public string RuleProtocol { get; set; }

        [Option("app", DefaultValue = "",
        HelpText = "Rule Application or Service")]
        public string RuleAppOrService { get; set; }
    }

    class DeleteRuleSubOptions
    {
        [Option('n', "rulename", DefaultValue = "",
        HelpText = "Rule Name")]
        public string RuleName { get; set; }

        [Option("alllocaldisabled", DefaultValue = false,
        HelpText = "Delete all local disabled rules")]
        public bool RuleDeleteLocalDisabled { get; set; }

        [Option('f', "force", DefaultValue = false,
        HelpText = "Force delete of rule, even if multiple rules exist")]
        public bool RuleDeleteForce { get; set; }

    }

    class StatusSubOptions
    {
        [Option('p', "profile", DefaultValue = null,
        HelpText = "Firewall profile.")]
        public ProfileType? Profile { get; set; }

        [Option('i', "interface", DefaultValue = false,
        HelpText = "List status by interface")]
        public bool byInterface { get; set; }
    }

    class RuleSubOptions : RuleSharedOptions
    {
        [Option('l', "list", DefaultValue = false,
        HelpText = "List out rules", MutuallyExclusiveSet = "ruleaction")]
        public bool List { get; set; }

        [Option('d', "duplicates", DefaultValue = false,
        HelpText = "List out duplicate rules", MutuallyExclusiveSet = "ruleaction")]
        public bool Duplicates { get; set; }

        [Option("profileduplicates", DefaultValue = false,
        HelpText = "List out rules that differ only by profile", MutuallyExclusiveSet = "ruleaction")]
        public bool ProfileDuplicates { get; set; }

        [Option('c', "count", DefaultValue = false,
        HelpText = "Count rules", MutuallyExclusiveSet = "ruleaction")]
        public bool Count { get; set; }

        [Option("scope", DefaultValue = "",
        HelpText = "Include local and/or group policy rules")]
        public string RuleScope { get; set; }

        [Option("shortapp", DefaultValue = false,
        HelpText = "Display executable name only in log output")]
        public bool RuleShortApp { get; set; }

        [Option("string", DefaultValue = false,
        HelpText = "Display rule as a string")]
        public bool RuleAsString { get; set; }
    }

    //requires admin
    class LogSubOptions
    {
        [Option('s', "status", DefaultValue = false,
        HelpText = "Display Status")]
        public bool LogStatus { get; set; }

        [Option('l', "list", DefaultValue = false,
        HelpText = "Display Blocked Connections")]
        public bool LogList { get; set; }

        [Option('t', "tail", DefaultValue = false,
        HelpText = "Tail Blocked Connections events")]
        public bool LogTail { get; set; }

        [Option("since", DefaultValue = "",
        HelpText = "Filter by time since datetime string", MutuallyExclusiveSet = "logfilter")]
        public string LogSince { get; set; }

        [Option("last", DefaultValue = "",
        HelpText = "Filter by time in last seconds, minutes, or hours", MutuallyExclusiveSet = "logfilter")]
        public string LogLast { get; set; }

        [Option("shortapp", DefaultValue = false,
        HelpText = "Display executable name only in log output")]
        public bool LogShortApp { get; set; }
    }

    //requires admin
    class UpdLogSubOptions
    {
        [Option('e', "enable", DefaultValue = false,
        HelpText = "Enable log", MutuallyExclusiveSet = "logaction")]
        public bool LogEnable { get; set; }

        [Option('d', "disable", DefaultValue = false,
        HelpText = "Disable log", MutuallyExclusiveSet = "logaction")]
        public bool LogDisable { get; set; }
    }

    class MSFWOptions
    {
        public MSFWOptions()
        {
            StatusVerb = new StatusSubOptions { Profile = ProfileType.all };
            UpdStatusVerb = new UpdStatusSubOptions { };
            LogVerb = new LogSubOptions { };
            RuleVerb = new RuleSubOptions { Profile = ProfileType.all };
            AddRuleVerb = new AddRuleSubOptions {  };
            InterfaceVerb = new InterfaceSubOptions { };
            UpdInterfaceVerb = new UpdInterfaceSubOptions { };
            UpdLogVerb = new UpdLogSubOptions { };
        }

        [VerbOption("status", HelpText = "Display firewall status.")]
        public StatusSubOptions StatusVerb { get; set; }

        [VerbOption("interface", HelpText = "Display included/excluded network interfaces.")]
        public InterfaceSubOptions InterfaceVerb { get; set; }

        [VerbOption("log", HelpText = "Display firewall log.")]
        public LogSubOptions LogVerb { get; set; }

        [VerbOption("rule", HelpText = "Display firewall rules.")]
        public RuleSubOptions RuleVerb { get; set; }

        [VerbOption("addrule", HelpText = "Add firewall rules.")]
        public AddRuleSubOptions AddRuleVerb { get; set; }

        [VerbOption("delrule", HelpText = "Delete firewall rules.")]
        public DeleteRuleSubOptions DeleteRuleVerb { get; set; }

        [VerbOption("updinterface", HelpText = "Update included/excluded interfaces.")]
        public UpdInterfaceSubOptions UpdInterfaceVerb { get; set; }

        [VerbOption("updlog", HelpText = "Enable/Disable firewall log.")]
        public UpdLogSubOptions UpdLogVerb { get; set; }

        [VerbOption("updstatus", HelpText = "Change firewall status.")]
        public UpdStatusSubOptions UpdStatusVerb { get; set; }

        [HelpVerbOption]
        public string GetUsage(string verb)
        {
            //https://github.com/freezy/dmd-extensions/blob/master/Console/Common/Options.cs
            var help = new HelpText
            {
                AdditionalNewLineAfterOption = false,
            };

            if (verb == null)
            {
                help.AddDashesToOption = false;
                help.AddOptions(this);
            }
            else
            {
                help.AddDashesToOption = true;
                switch (verb)
                {
                    case "rule":
                        help.AddOptions(RuleVerb);
                        break;
                    case "status":
                        help.AddOptions(StatusVerb);
                        break;
                    case "interface":
                        help.AddOptions(InterfaceVerb);
                        break;
                    case "log":
                        help.AddOptions(LogVerb);
                        break;
                    case "addrule":
                        help.AddOptions(AddRuleVerb);
                        break;
                    case "delrule":
                        help.AddOptions(DeleteRuleVerb);
                        break;
                    case "updinterface":
                        help.AddOptions(UpdInterfaceVerb);
                        break;
                    case "updlog":
                        help.AddOptions(UpdLogVerb);
                        break;
                    case "updstatus":
                        help.AddOptions(UpdStatusVerb);
                        break;
                }
            }
            return help;
            //return HelpText.AutoBuild(this, verb);
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            string adminError = "Unable to complete task due to limited access rights. Please run again as an administrator.";
            string invokedVerb = "status";
            object invokedVerbInstance = new StatusSubOptions();

            var options = new MSFWOptions();
            try
            {
                if (!CommandLine.Parser.Default.ParseArguments(args, options,
                  (verb, subOptions) =>
                  {
                      // if parsing succeeds the verb name and correct instance
                      // will be passed to onVerbCommand delegate (string,object)
                      invokedVerb = verb;
                      invokedVerbInstance = subOptions;
                  }))
                {
                    Environment.Exit(CommandLine.Parser.DefaultExitCodeFail);
                }
            }
            catch (NullReferenceException)
            {
                Console.WriteLine("Please pass a subcommand: status, rule, or log");
                Environment.Exit(0);
            }

            var msfw = new MSFirewall();

            if (invokedVerb == "status")
            {
                var statusSubOptions = (StatusSubOptions)invokedVerbInstance;
                msfw.updateCurrentProfile();

                var profiles = getProfilesInScope(statusSubOptions.Profile);

                var columns = new List<string>() {
                    "Profile",
                    "Status",
                    "Active",
                    "Inbound",
                    "Outbound"
                };

                var strFormat = "\"{0}\",\"{1}\",\"{2}\",\"{3}\",\"{4}\"";

                if (statusSubOptions.byInterface)
                {
                    strFormat = "\"{0}\",\"{1}\",\"{2}\",\"{3}\",\"{4}\",\"{5}\",\"{6}\",\"{7}\"";
                    columns.Add("Interface");
                    columns.Add("Network");
                    columns.Add("Excluded");
                }

                Console.WriteLine("\"" + String.Join(",", columns).Replace(",","\",\"") + "\"");

                foreach (var p in profiles)
                {
                    //find excluded interfaces
                    var excluded = msfw.getExcludedInterfaces(p);

                    var curProfileName = MSFirewall.getProfileName(p);
                    var networks = new Dictionary<string, List<string>>();
                    if (statusSubOptions.byInterface)
                    {
                        networks = msfw.NetworksByProfileDict(p, Microsoft.WindowsAPICodePack.Net.NetworkConnectivityLevels.Connected);
                    }
 
                    if(statusSubOptions.byInterface && networks.Keys.Count > 0)
                    {
                        foreach (var network in networks)
                        {
                            foreach(var netint in network.Value)
                            {
                                Console.WriteLine(strFormat,
                                                  curProfileName,
                                                  msfw.isEnabledStr(p, false),
                                                  msfw.isActiveStr(p, false),
                                                  msfw.getCurInboundAction(p),
                                                  msfw.getCurOutboundAction(p),
                                                  netint,
                                                  network.Key,
                                                  (excluded.ContainsKey(network.Key)) ? "Excluded" : "Included");
                            }
                        }
                    }
                    else
                    {
                        if (statusSubOptions.byInterface)
                        {
                            Console.WriteLine(strFormat,
                                              curProfileName,
                                              msfw.isEnabledStr(p, false),
                                              msfw.isActiveStr(p, false),
                                              msfw.getCurInboundAction(p),
                                              msfw.getCurOutboundAction(p),
                                              "",
                                              "",
                                              "");
                        }
                        else
                        {
                            Console.WriteLine(strFormat,
                                              curProfileName,
                                              msfw.isEnabledStr(p, false),
                                              msfw.isActiveStr(p, false),
                                              msfw.getCurInboundAction(p),
                                              msfw.getCurOutboundAction(p));
                        }
                    }                    
                }
                //Console.WriteLine("'Windows Firewall' Service: {0}", msfw.getServiceState());
            }
            else if (invokedVerb == "interface")
            {
                var interfaceSubOptions = (InterfaceSubOptions)invokedVerbInstance;

                var interfaces = msfw.getInterfaces();
                var exDo = msfw.getExcludedInterfaces(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN);
                var exPr = msfw.getExcludedInterfaces(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE);
                var exPu = msfw.getExcludedInterfaces(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC);

                Console.WriteLine("\"Interface\",\"Domain\",\"Private\",\"Public\"");
                foreach (string cur in interfaces) {
                    if(interfaceSubOptions.IntName == "" || interfaceSubOptions.IntName.ToLower() == cur.ToLower())
                    {
                        Console.WriteLine("\"{0}\",\"{1}\",\"{2}\",\"{3}\"",
                            cur,
                            (exDo.ContainsKey(cur) ? "Excluded" : "Included"),
                            (exPr.ContainsKey(cur) ? "Excluded" : "Included"),
                            (exPu.ContainsKey(cur) ? "Excluded" : "Included"));
                    }
                }
            }
            else if (invokedVerb == "updstatus")
            {
                var updStatusSubOptions = (UpdStatusSubOptions)invokedVerbInstance;

                if (updStatusSubOptions.Profile == null)
                {
                    endProgOnError("Profile required. Must be one of '-p [domain|private|public]'");
                }

                if (updStatusSubOptions.Status == null &&
                    updStatusSubOptions.Inbound == null &&
                    updStatusSubOptions.Outbound == null)
                {
                    endProgOnError("Must pass '--status [enable,disable]','--inbound [allow,block]', or '--outbound [allow,block]'");
                }

                if (updStatusSubOptions.Status != null)
                {
                    if (updStatusSubOptions.Status.ToString().Substring(0, 1).ToLower() == "e")
                    {
                        Console.WriteLine("Enable firewall for all profiles. Not yet implemented");
                    }
                    else if (updStatusSubOptions.Status.ToString().Substring(0, 1).ToLower() == "d")
                    {
                        Console.WriteLine("Disable firewall for all profiles. Not yet implemented");
                    }
                    else
                    {
                        endProgOnError("Unknown value for '--status' Must be '--status enable' or '--status disable'");
                    }
                }

                if (updStatusSubOptions.Inbound != null)
                {
                    var profile = getProfilesInScope(updStatusSubOptions.Profile)[0];

                    if (updStatusSubOptions.Inbound == ActionType.a ||
                        updStatusSubOptions.Inbound == ActionType.allow)
                    {
                        try
                        {
                            msfw.setInboundAction(profile, NET_FW_ACTION_.NET_FW_ACTION_ALLOW);
                            Console.WriteLine("Set " + updStatusSubOptions.Profile + " default inbound to allow.");
                        }
                        catch (UnauthorizedAccessException)
                        {
                            Console.WriteLine(adminError);
                        }
                    }
                    else if (updStatusSubOptions.Inbound == ActionType.b ||
                             updStatusSubOptions.Inbound == ActionType.block)
                    {
                        try
                        {
                            msfw.setInboundAction(profile, NET_FW_ACTION_.NET_FW_ACTION_BLOCK);
                            Console.WriteLine("Set " + updStatusSubOptions.Profile + " default inbound to block.");
                        }
                        catch (UnauthorizedAccessException)
                        {
                            Console.WriteLine(adminError);
                        }
                    }
                    else
                    {
                        endProgOnError("Unknown value for '--inbound' Must be '--inbound allow' or '--inbound block'");
                    }
                }

                if (updStatusSubOptions.Outbound != null)
                {
                    var profile = getProfilesInScope(updStatusSubOptions.Profile)[0];

                    if (updStatusSubOptions.Outbound == ActionType.a ||
                        updStatusSubOptions.Outbound == ActionType.allow)
                    {
                        msfw.setOutboundAction(profile, NET_FW_ACTION_.NET_FW_ACTION_ALLOW);
                        Console.WriteLine("Set " + updStatusSubOptions.Profile + " default outbound to allow.");
                    }
                    else if (updStatusSubOptions.Outbound == ActionType.b ||
                             updStatusSubOptions.Outbound == ActionType.block)
                    {
                        msfw.setOutboundAction(profile, NET_FW_ACTION_.NET_FW_ACTION_BLOCK);
                        Console.WriteLine("Set " + updStatusSubOptions.Profile + " default outbound to block.");
                    }
                    else
                    {
                        endProgOnError("Unknown value for '--outbound' Must be '--outbound allow' or '--outbound block'");
                    }
                }
            }
            else if (invokedVerb == "updinterface")
            {
                var updIntSubOptions = (UpdInterfaceSubOptions)invokedVerbInstance;

                var profiles = getProfilesInScope(updIntSubOptions.Profile);

                if (updIntSubOptions.IntName.Trim() == "")
                {
                    endProgOnError("Unable to find an interface name. Pass '-n <interfacename>'");
                }

                var interfaces = msfw.getInterfaces();

                foreach (var p in profiles)
                {
                    if(!interfaces.Contains(updIntSubOptions.IntName, StringComparer.OrdinalIgnoreCase))
                    {
                        Console.WriteLine("Unable to find interface: " + updIntSubOptions.IntName);
                        endProgOnError("Run 'msfw interface' to see a list of interface name");
                    }

                    var result = -1;

                    if (updIntSubOptions.ActionInclude)
                    {
                        result = msfw.addIncludedInterface(p, updIntSubOptions.IntName);
                        if(result == 1)
                        {
                            Console.WriteLine("'{0}' already included with '{1}' profile.", updIntSubOptions.IntName, MSFirewall.getProfileName(p));
                        }
                        else
                        {
                            Console.WriteLine("'{0}' included with '{1}' profile", updIntSubOptions.IntName, MSFirewall.getProfileName(p));
                        }
                    }
                    else if (updIntSubOptions.ActionExclude)
                    {
                        result = msfw.addExcludedInterface(p, updIntSubOptions.IntName);
                        if (result == 1)
                        {
                            Console.WriteLine("Interface not found: " + updIntSubOptions.IntName);
                        }
                        else
                        {
                            Console.WriteLine("'{0}' excluded from '{1}' profile", updIntSubOptions.IntName, MSFirewall.getProfileName(p));
                        }
                    }
                    else
                    {
                        //this shouldn't ever happen
                        endProgOnError("Pass either '--include' or '--exclude' action in input.");
                    }
                }
            }
            else if (invokedVerb == "rule")
            {
                var ruleSubOptions = (RuleSubOptions)invokedVerbInstance;
                var ruleList = new List<MSFirewallRule>();
                var dupList = new Dictionary<string,int>();
                var dupListWithoutProfile = new Dictionary<string, int>();

                if (ruleSubOptions.RuleScope != "" && ruleSubOptions.RuleScope.Substring(0, 1).ToLower() == "l")
                {
                    ruleList = msfw.getLocalRules(true);
                }
                else if (ruleSubOptions.RuleScope != "" && ruleSubOptions.RuleScope.Substring(0, 1).ToLower() == "p")
                {
                    ruleList = msfw.getPolicyRules();
                }
                else if (ruleSubOptions.RuleScope == "" || ruleSubOptions.RuleScope.Substring(0, 1).ToLower() == "a")
                {
                    ruleList = msfw.getLocalRules(true);
                    ruleList.AddRange(msfw.getPolicyRules());
                }
                else
                {
                    endProgOnError("Unknown scope. Use '--scope local' or '--scope policy'");
                }

                if (ruleSubOptions.Duplicates)
                {
                    foreach(var r in ruleList)
                    {
                        if (dupList.ContainsKey(r.ToString())) {
                            dupList[r.ToString()] = 1;
                        } else {
                            dupList[r.ToString()] = 0;
                        }
                    }
                }

                if (ruleSubOptions.ProfileDuplicates)
                {
                    foreach (var r in ruleList)
                    {
                        var dr = new MSFirewallRule(r.ToString());
                        dr.rule.Profiles = (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_ALL; // hrm...make a profile setter?

                        if (dupListWithoutProfile.ContainsKey(dr.ToString()))
                        {
                            dupListWithoutProfile[dr.ToString()] = 1;
                        }
                        else
                        {
                            dupListWithoutProfile[dr.ToString()] = 0;
                        }
                    }
                }


                var ruleCnt = 0;

                Console.WriteLine("\"{0}\",\"{1}\",\"{2}\",\"{3}\",\"{4}\",\"{5}\",\"{6}\",\"{7}\",\"{8}\"",
                                    "Profiles",
                                    "Action",
                                    "Dir",
                                    "App",
                                    "Local",
                                    "Remote",
                                    "Proto",
                                    "Ext",
                                    "Name");

                foreach (MSFirewallRule rule in ruleList)
                {
                    //Console.WriteLine("Evaluate rule: " + rule.Name);
                    var found = new Dictionary<string, bool>();

                    found["Status"] = true;

                    if (ruleSubOptions.RuleName != "")
                    {
                        found["Name"] = (ruleSubOptions.RuleName.ToLower() == rule.Name.ToLower());

                        //look for a like a regex
                        if (!found["Name"])
                        {
                            if (ruleSubOptions.RuleName.Contains('$') ||
                            ruleSubOptions.RuleName.Contains('^') ||
                            ruleSubOptions.RuleName.Contains(".*") ||
                            ruleSubOptions.RuleName.Contains(".+") ||
                            ruleSubOptions.RuleName.Contains("\\d") ||
                            ruleSubOptions.RuleName.Contains("\\w") ||
                            ruleSubOptions.RuleName.Contains("\\s"))
                            {
                                var m = Regex.Match(rule.Name, ruleSubOptions.RuleName);
                                found["Name"] = m.Success;
                            }
                        }
                    }

                    if (ruleSubOptions.RuleStatus.ToLower() != "all" && ruleSubOptions.RuleStatus.ToLower() != "")
                    {
                        found["Status"] = ((ruleSubOptions.RuleStatus.Substring(0, 1).ToLower() == "e" && rule.Enabled) ||
                                            (ruleSubOptions.RuleStatus.Substring(0, 1).ToLower() == "d" && !rule.Enabled));
                    }

                    if (ruleSubOptions.Profile != null)
                    {
                        var curProfiles = MSFirewall.getProfileNames((NET_FW_PROFILE_TYPE2_)rule.Profiles).ToLower();
                        found["Profile"] = curProfiles.Contains(ruleSubOptions.Profile.ToString().ToLower()) || curProfiles.Contains("all");
                    }

                    if (ruleSubOptions.RuleLocal.Length > 1 || ruleSubOptions.RuleLocal[0] != "")
                    {
                        found["Local"] = matchAddressAndPorts(rule.LocalAddresses, rule.LocalPorts, ruleSubOptions.RuleLocal);
                    }

                    if (ruleSubOptions.RuleRemote.Length > 1 || ruleSubOptions.RuleRemote[0] != "")
                    {
                        found["Remote"] = matchAddressAndPorts(rule.RemoteAddresses, rule.RemotePorts, ruleSubOptions.RuleRemote);
                    }

                    if (ruleSubOptions.RuleDirection != null)
                    {
                        found["Dir"] = matchDirection(rule.DirectionName, ruleSubOptions.RuleDirection.ToString());
                    }

                    if (ruleSubOptions.RuleAction != "")
                    {
                        found["Action"] = matchAction(rule.ActionName, ruleSubOptions.RuleAction);
                    }

                    if (ruleSubOptions.RuleAppOrService != "")
                    {
                        found["App"] = matchAppOrService(rule.AppAndService, ruleSubOptions.RuleAppOrService);
                    }

                    if (ruleSubOptions.RuleProtocol != "")
                    {
                        found["Protocol"] = matchProtocol(rule.ProtocolName, ruleSubOptions.RuleProtocol);
                    }

                    if (ruleSubOptions.RuleExtended != "")
                    {
                        found["RuleExtended"] = (rule.Extended.ToString().Substring(0, 1).ToLower() == ruleSubOptions.RuleExtended.Substring(0, 1).ToLower());
                    }

                    // direction app srcip srcport dstip dstport protocol

                    if(ruleSubOptions.Duplicates) {
                        found["Duplicates"] = (dupList[rule.ToString()] == 1);
                    }

                    if(ruleSubOptions.ProfileDuplicates) {
                        var dr = new MSFirewallRule(rule.ToString());
                        dr.rule.Profiles = (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_ALL; // hrm...make a profile setter?

                        found["ProfileDuplicates"] = (dupListWithoutProfile[dr.ToString()] == 1);
                    }

                    if (found.All(f => f.Value == true))
                    {
                        if (ruleSubOptions.Count)
                        {
                            ruleCnt++;
                        }
                        else
                        {
                            if (ruleSubOptions.RuleAsString)
                            {
                                Console.WriteLine(rule.ToString());
                            }
                            else
                            {
                                Console.Write("\"{0}\",\"{1}\",\"{2}\",\"{3}\",\"{4}:{5}\",\"{6}:{7}\",\"{8}\",\"{9}\",\"{10}\"\r\n",
                                    MSFirewall.getProfileNamesAbbrev((NET_FW_PROFILE_TYPE2_)rule.Profiles),
                                    rule.ActionName,
                                    rule.DirectionName,
                                    (ruleSubOptions.RuleShortApp) ? Path.GetFileName(rule.AppAndService) : rule.AppAndService,
                                    rule.LocalAddresses,
                                    rule.LocalPorts,
                                    rule.RemoteAddresses,
                                    rule.RemotePorts,
                                    rule.ProtocolName,
                                    rule.Extended,
                                    rule.Name);
                                //Console.WriteLine(rule.rule.GetHashCode());
                            }
                        }
                        //Console.WriteLine(msfw.PickleRule(rule));
                        //Console.WriteLine(rule.IcmpTypesAndCodes);
                    }
                }

                if (ruleSubOptions.Count)
                {
                    Console.WriteLine("Rule count: " + ruleCnt.ToString());
                }
            }
            else if (invokedVerb == "updlog")
            {
                var updLogSubOptions = (UpdLogSubOptions)invokedVerbInstance;
                if (updLogSubOptions.LogEnable)
                {
                    Console.WriteLine("Action: Enable log (requires admin privileges)");
                    msfw.enableWFPFailureAuditing();
                }
                else if (updLogSubOptions.LogDisable)
                {
                    Console.WriteLine("Action: Disable log (requires admin privileges)");
                    msfw.disableWFPFailureAuditing();
                }
                else
                {
                    endProgOnError("Unknown updlog command");
                }
            }
            else if (invokedVerb == "log")
            {
                var logSubOptions = (LogSubOptions)invokedVerbInstance;
                if (logSubOptions.LogList)
                {
                    var dt = DateTime.Now;
                    if (logSubOptions.LogLast != "")
                    {
                        Match m = Regex.Match(logSubOptions.LogLast, @"^\s*(\d+)\s*(.+)");
                        if (m.Success)
                        {
                            var dur = Int32.Parse(m.Groups[1].ToString());
                            var durtype = m.Groups[2].ToString().Substring(0, 1).ToLower();
                            if (durtype == "h")
                            {
                                dt = dt.Add(new TimeSpan(-dur, 0, 0));
                            }
                            else if (durtype == "m")
                            {
                                dt = dt.Add(new TimeSpan(0, -dur, 0));
                            }
                            else if (durtype == "s")
                            {
                                dt = dt.Add(new TimeSpan(0, 0, -dur));
                            }
                            else
                            {
                                endProgOnError("Unable to parse input as hour, minute, or second: " + logSubOptions.LogLast);
                            }
                        }
                        else
                        {
                            endProgOnError("Unable to parse input --last string: " + logSubOptions.LogLast);
                        }
                    }
                    else if (logSubOptions.LogSince != "")
                    {
                        dt = DateTime.Parse(logSubOptions.LogSince);
                    }
                    else
                    {
                        dt = dt.Add(new TimeSpan(0, -1, 0));
                    }
                    Console.WriteLine("Retrieving Logs since: " + dt.ToString("yyyy-MM-dd HH:mm:ss"));
                    dt = TimeZoneInfo.ConvertTime(dt, TimeZoneInfo.Local, TimeZoneInfo.Utc);
                    Console.WriteLine("Retrieving Logs since (UTC): " + dt.ToString("yyyy-MM-dd HH:mm:ss"));
                    msfw.listAuditFailures(dt, logSubOptions.LogShortApp);
                }
                else if (logSubOptions.LogTail)
                {
                    try
                    {
                        msfw.tailLog();
                    }
                    catch (System.Security.SecurityException e)
                    {
                        Console.WriteLine("Unable to tail security log. Tail log requires admin rights: " + e.Message);
                    }
                }
                else
                {
                    var ret = msfw.isWFPFailureAuditingEnabled();
                    var status = "";
                    if (ret.ContainsKey(false) && ret[false] != "")
                    {
                        status = "Unknown (" + ret[false] + ")";
                    }
                    else
                    {
                        status = ret.Keys.ToList()[0].ToString();
                    }
                    Console.WriteLine("Logging Enabled: {0}", status);
                }
            }
            else if (invokedVerb == "addrule")
            {
                var addRuleSubOptions = (AddRuleSubOptions)invokedVerbInstance;
                INetFwRule2 rule = (INetFwRule2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));

                //defaults
                rule.Enabled = true;
                rule.Description = "";
                rule.InterfaceTypes = "All";

                //Name
                //Required by msfw; not required by firewall class. Name does not have to be unique either.
                addRuleSubOptions.RuleName = addRuleSubOptions.RuleName.Trim();
                if (addRuleSubOptions.RuleName == "")
                {
                    endProgOnError("Missing required rule name. Pass '--rulename \"<insertrulename>\"'");
                }

                //MS requirement as it conflicts with their 'netsh advfirewall rule=all' command
                if (addRuleSubOptions.RuleName.ToLower() == "all")
                {
                    endProgOnError("Rule name is not allowed to be 'all'");
                }

                rule.Name = addRuleSubOptions.RuleName;

                //Description
                //rule.Description = addRuleSubOptions.RuleDescription;

                //Grouping
                //rule.Grouping = addRuleSubOptions.RuleGrouping;

                //Profile
                //TODO: add support for multiple profiles
                //Default: all
                if (addRuleSubOptions.Profile.Length > 0)
                {
                    int addprofile = 0x0;
                    foreach (var p in addRuleSubOptions.Profile)
                    {
                        switch (p.ToLower())
                        {
                            case "do":
                            case "domain":
                                addprofile = (int)addprofile | (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN;
                                break;
                            case "pr":
                            case "private":
                                addprofile = (int)addprofile | (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE;
                                break;
                            case "pu":
                            case "public":
                                addprofile = (int)addprofile | (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC;
                                break;
                            case "al":
                            case "all":
                                addprofile = (int)addprofile | (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_ALL;
                                break;
                        }
                    }
                    rule.Profiles = addprofile;
                }

                //Protocol
                //Default is all
                if (addRuleSubOptions.RuleProtocol != "")
                {
                    try
                    {
                        rule.Protocol = (int)Enum.Parse(typeof(ProtocolType), addRuleSubOptions.RuleProtocol, true);
                    } catch (Exception e)
                    {
                        endProgOnError("Unable to parse --protocol. Check spelling and try again.");
                    }
                }

                //Local addresses and ports
                if (addRuleSubOptions.RuleLocal.Length > 0 &&
                    addRuleSubOptions.RuleLocal[0] != "" &&
                    addRuleSubOptions.RuleLocal[0] != "*" &&
                    addRuleSubOptions.RuleLocal[0] != "*:*" &&
                    addRuleSubOptions.RuleLocal[0].ToLower() != "any")
                {
                    var pA = parseAddressAndPorts(addRuleSubOptions.RuleLocal);

                    if (pA["addresses"].Count > 0)
                    {
                        rule.LocalAddresses = String.Join(",", pA["addresses"].Keys.ToArray());
                    }

                    if (pA["ports"].Count > 0)
                    {
                        var portList = String.Join(",", pA["ports"].Keys.ToArray());
                        if (rule.Protocol != 6 && rule.Protocol != 17 && portList != "*")
                        {
                            endProgOnError("You must specify UDP or TCP for protocol if filtering by port. Example: '--protocol udp' or '--protocol tcp'");
                        }

                        if (portList != "*")
                        {
                            rule.LocalPorts = portList;
                        }
                    }
                }

                //Remote addresses and ports
                if (addRuleSubOptions.RuleRemote.Length > 0 &&
                    addRuleSubOptions.RuleRemote[0] != "" &&
                    addRuleSubOptions.RuleRemote[0] != "*" &&
                    addRuleSubOptions.RuleRemote[0] != "*:*" &&
                    addRuleSubOptions.RuleRemote[0].ToLower() != "any")
                {
                    var pA = parseAddressAndPorts(addRuleSubOptions.RuleRemote);

                    if (pA["addresses"].Count > 0)
                    {
                        rule.RemoteAddresses = String.Join(",", pA["addresses"].Keys.ToArray());
                    }

                    if (pA["ports"].Count > 0)
                    {
                        var portList = String.Join(",", pA["ports"].Keys.ToArray());
                        if (rule.Protocol != 6 && rule.Protocol != 17 && portList != "*")
                        {
                            endProgOnError("You must specify UDP or TCP for protocol if filtering by port. Example: '--protocol udp' or '--protocol tcp'");
                        }

                        if (portList != "*")
                        {
                            rule.RemotePorts = portList;
                        }
                    }
                }

                //Application
                //Default is all
                if (addRuleSubOptions.RuleAppOrService != "")
                {
                    rule.ApplicationName = addRuleSubOptions.RuleAppOrService;
                }

                //Action
                //required
                if (addRuleSubOptions.RuleAction != "")
                {
                    if (addRuleSubOptions.RuleAction.ToLower().Substring(0, 1) == "a")
                    {
                        rule.Action = NET_FW_ACTION_.NET_FW_ACTION_ALLOW;
                    }
                    else if (addRuleSubOptions.RuleAction.ToLower().Substring(0, 1) == "b")
                    {
                        rule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
                    }
                    else
                    {
                        endProgOnError("Unknown action: " + rule.Action);
                    }
                }
                else
                {
                    endProgOnError("Missing required 'action' parameter. Please pass '--action allow' or '--action block'");
                }

                //Direction
                //required
                if (addRuleSubOptions.RuleDirection != null)
                {
                    if (addRuleSubOptions.RuleDirection.ToString().ToLower().Substring(0, 1) == "i")
                    {
                        rule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN;
                    }
                    else if (addRuleSubOptions.RuleDirection.ToString().ToLower().Substring(0, 1) == "o")
                    {
                        rule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT;
                    }
                    else
                    {
                        endProgOnError("Unknown direction: " + addRuleSubOptions.RuleDirection);
                    }
                }
                else
                {
                    endProgOnError("Missing required 'dir' parameter. Please pass '--dir in' or '--dir out'");
                }

                try
                {
                    msfw.addRule(rule);
                    Console.WriteLine("Added rule: " + rule.Name);
                }
                catch (UnauthorizedAccessException)
                {
                    Console.WriteLine(adminError);
                }
            }
            else if (invokedVerb == "delrule")
            {
                var deleteRuleSubOptions = (DeleteRuleSubOptions)invokedVerbInstance;
                var cnt = 0;

                if (deleteRuleSubOptions.RuleDeleteLocalDisabled)
                {
                    cnt = msfw.deleteDisabledLocalRules();
                }
                else
                {
                    if (deleteRuleSubOptions.RuleName == "")
                    {
                        endProgOnError("Missing required '-n' parameter. Please pass '-n <rulename>'");
                    }

                    try
                    {
                        var existing = msfw.countLocalRules(deleteRuleSubOptions.RuleName);
                        if (existing > 1 && !deleteRuleSubOptions.RuleDeleteForce)
                        {
                            Console.Write(existing + " rules found with this name. Are you sure you want to delete all of them? [y\\N]: ");
                            var choice = Console.ReadLine();
                            if (choice == "" || choice.Substring(0,1).ToLower() != "y") {
                                Environment.Exit(0);
                            }
                        }
                        cnt = msfw.deleteLocalRule(deleteRuleSubOptions.RuleName);
                    }
                    catch(UnauthorizedAccessException)
                    {
                        Console.WriteLine(adminError);
                    }
                }

                Console.WriteLine("Deleted " + cnt + " rule(s).");
            }
        }


        /* parseAddressAndPorts
         * inputStr: colon-delimited string. Ex. *:*, 192.168.2.1:*, 10.10.10.10:443
         */
        public static Dictionary<string,Dictionary<string,int>> parseAddressAndPorts(string[] inputStr)
        {
            var any = new Dictionary<string,int>() {{"any",1}, {"*",1},{"*:*",1}};

            var portsAddresses = new Dictionary<string, Dictionary<string,int>>();
            portsAddresses.Add("ports", new Dictionary<string, int>());
            portsAddresses.Add("addresses", new Dictionary<string, int>());

            foreach (var s in inputStr)
            {
                //if search string is any address/port
                if (s == "*" || s.ToLower() == "any" || s == "*:*")
                {
                    portsAddresses["ports"]["*"] = 1;
                    portsAddresses["addresses"]["*"] = 1;
                }
                else
                {
                    //todo: ipv6 fail
                    var parts = s.Split(':');
                    var curPort = "";
                    var curAddress = "";

                    //our concern is that if a user passes 1.1.1.1:20 2.2.2.2:30
                    //that they don't realize this actually ends up being:
                    //1.1.1.1,2.2.2.2:20,30
                    //so let's allow either all unique ports or all unique addresses
                    //if passed in this form.
                    //this address:port format is good for searching, but it's bad for creating
                    if (parts.Length == 2 && Regex.IsMatch(parts[1], @"^\d+$"))
                    {
                        //we have a address and port
                        curAddress = parts[0];
                        curPort = parts[1];
                    }
                    else if(parts.Length == 1 && Regex.IsMatch(parts[0], @"^\d+$"))
                    {
                        //we have a port only
                        curPort = parts[0];
                    }
                    else
                    {
                        //we have an address only
                        curAddress = parts[0];            
                    }

                    if (any.ContainsKey(curPort))
                    {
                        //it's just a variant on "any"
                        portsAddresses["ports"]["*"] = 1;
                    }
                    else if(curPort != "")
                    {
                        portsAddresses["ports"][curPort] = 1;
                    }

                    if (curAddress != "")
                    {
                        portsAddresses["addresses"][curAddress] = 1;
                    }
                }
            }

            if(portsAddresses["ports"].Keys.Count == 0)
            {
                portsAddresses["ports"]["*"] = 1;
            }

            if(portsAddresses["addresses"].Keys.Count == 0)
            {
                portsAddresses["addresses"]["*"] = 1;
            }

            if (portsAddresses["ports"].Keys.Count > 1 && portsAddresses["addresses"].Keys.Count > 1)
            {
                endProgOnError("Unable to parse addresses and ports. The address list or the port list must be unique.");
            }

            return portsAddresses;
        }

        public static bool matchAddressAndPorts(string ruleAddresses, string rulePorts, string[] searchStr)
        {
            //Console.WriteLine("Evaluate a:p=" + ruleAddresses + ':' + rulePorts);
            var foundAddr = false; //determines if addresses match
            var foundPort = false; //determines if ports match

            var searchStrAddresses = ""; //searchStr[0]
            var searchStrPorts     = ""; //searchStr[1]

            var addresses = new List<string>();
            var ports     = new List<string>();

            foreach (var s in searchStr)
            {
                //if search string is any address/port
                if (s == "*" || s.ToLower() == "any" || s == "*:*")
                {
                    //then only match on addresses/ports that are any too
                    if ((ruleAddresses == "*" || ruleAddresses == null) &&
                        (rulePorts == "*" || rulePorts == null))
                    {
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }

                if (!s.Contains(':'))
                {
                    endProgOnError("Search string must be in format address:port");
                }

                var searchStrParts = s.Split(':');
                searchStrAddresses = searchStrParts[0];
                searchStrPorts = searchStrParts[1];

                if (searchStrAddresses == "*")
                {
                    foundAddr = true;
                }
                else
                {
                    
                    addresses = searchStrAddresses.Split(',').ToList();
                    //Console.WriteLine("search addresses:" + searchStrAddresses);
                    //Console.WriteLine("rule addresses:" + ruleAddresses);
                    foundAddr = ruleAddresses.Split(',').Intersect(addresses).Any();
                }

                if (foundAddr && searchStrPorts == "*")
                {
                    foundPort = true;
                }
                else
                {
                    ports = searchStrPorts.Split(',').ToList();
                    foundPort = rulePorts.Split(',').Intersect(ports).Any();
                }
            }
            //Console.WriteLine("foundport:" + foundPort);
            return (foundAddr && foundPort);
        }

        public static bool matchProtocol(string ruleProtocolName, string searchProtocol)
        {
            if (ruleProtocolName.ToLower() == searchProtocol.ToLower())
            {
                return true;
            }
            return false;
        }

        public static List<NET_FW_PROFILE_TYPE2_> getProfilesInScope(ProfileType? profile)
        {
            var profileStr = profile.ToString();

            var profiles = new List<NET_FW_PROFILE_TYPE2_>()
                {
                    NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN,
                    NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE,
                    NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC
                };

            switch (profileStr)
            {
                case "do":
                case "domain":
                    profiles = new List<NET_FW_PROFILE_TYPE2_>() { NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN };
                    break;
                case "private":
                case "pr":
                    profiles = new List<NET_FW_PROFILE_TYPE2_>() { NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE };
                    break;
                case "public":
                case "pu":
                    profiles = new List<NET_FW_PROFILE_TYPE2_>() { NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC };
                    break;
            }

            return profiles;
        }

        public static List<NET_FW_PROFILE_TYPE2_> getProfilesInScope(NET_FW_PROFILE_TYPE2_ profile)
        {
            var profiles = new List<NET_FW_PROFILE_TYPE2_>()
                {
                    NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN,
                    NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE,
                    NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC
                };

            switch (profile.ToString())
            {
                case "do":
                    profiles = new List<NET_FW_PROFILE_TYPE2_>() { NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN };
                    break;
                case "pr":
                    profiles = new List<NET_FW_PROFILE_TYPE2_>() { NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE };
                    break;
                case "pu":
                    profiles = new List<NET_FW_PROFILE_TYPE2_>() { NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC };
                    break;
            }

            return profiles;
        }

        public static List<NET_FW_PROFILE_TYPE2_> getProfilesInScope(string profile)
        {
            var profiles = new List<NET_FW_PROFILE_TYPE2_>()
                {
                    NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN,
                    NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE,
                    NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC
                };

            if (profile != "" && profile.Length > 1)
                profile = profile.Substring(0, 2).ToLower();

            switch (profile)
            {
                case "do":
                    profiles = new List<NET_FW_PROFILE_TYPE2_>() { NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN };
                    break;
                case "pr":
                    profiles = new List<NET_FW_PROFILE_TYPE2_>() { NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE };
                    break;
                case "pu":
                    profiles = new List<NET_FW_PROFILE_TYPE2_>() { NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC };
                    break;
            }

            return profiles;
        }

        public static bool matchAppOrService(string ruleAppAndService, string searchAppOrService)
        {
            var found = false;
            searchAppOrService = searchAppOrService.ToLower();
            ruleAppAndService = ruleAppAndService.ToLower();

            if (ruleAppAndService == searchAppOrService)
            {
                found = true;
            }

            if (!found)
            {
                if (ruleAppAndService.Contains(':'))
                {
                    //Console.WriteLine(ruleAppAndService);
                    //Console.WriteLine(searchAppOrService);
                    var AppAndServiceParts = ruleAppAndService.Split(':');
                    if (Path.GetFileName(AppAndServiceParts[0]) == searchAppOrService ||
                       Path.GetFileName(AppAndServiceParts[1]) == searchAppOrService)
                    {
                        found = true;
                    }
                }
                else
                {
                    if (Path.GetFileName(ruleAppAndService) == searchAppOrService)
                    {
                        found = true;
                    }
                }
            }
            return found;
        }

        public static bool matchDirection(string ruleDirectionName, string searchDirection)
        {
            if (ruleDirectionName.Substring(0,1).ToLower() == searchDirection.Substring(0,1).ToLower())
            {
                return true;
            }
            return false;
        }

        public static bool matchAction(string ruleActionName, string searchAction)
        {
            if (ruleActionName.Substring(0, 1).ToLower() == searchAction.Substring(0, 1).ToLower())
            {
                return true;
            }
            return false;
        }

        public static void endProgOnError(string error)
        {
            Console.WriteLine("ERROR: " + error);
            Environment.Exit(1);
        }

            /*
            var msfw = new MSFirewall();

            Console.WriteLine("FW Service State: {0}", msfw.getServiceState());
            Console.WriteLine();

            Console.WriteLine("Domain enabled: {0}", msfw.isEnabled(NetFwTypeLib.NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN));
            Console.WriteLine("Private enabled: {0}", msfw.isEnabled(NetFwTypeLib.NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE));
            Console.WriteLine("Public enabled: {0}", msfw.isEnabled(NetFwTypeLib.NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC));
            Console.WriteLine();

            Console.WriteLine("Domain default inbound: {0}", msfw.getCurInboundAction(NetFwTypeLib.NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN));
            Console.WriteLine("Private default inbound: {0}", msfw.getCurInboundAction(NetFwTypeLib.NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE));
            Console.WriteLine("Public default inbound: {0}", msfw.getCurInboundAction(NetFwTypeLib.NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC));
            Console.WriteLine();

            Console.WriteLine("Domain default outbound: {0}", msfw.getCurOutboundAction(NetFwTypeLib.NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN));
            Console.WriteLine("Private default outbound: {0}", msfw.getCurOutboundAction(NetFwTypeLib.NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE));
            Console.WriteLine("Public default outbound: {0}", msfw.getCurOutboundAction(NetFwTypeLib.NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC));
            Console.WriteLine();

            var networks = msfw.ListConnectedNetworkProfiles(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN);
            foreach (var network in networks)
            {
                Console.WriteLine("Domain:" + network);
            }

            var networks2 = msfw.ListConnectedNetworkProfiles(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE);
            foreach (var network in networks2)
            {
                Console.WriteLine("Private:" + network);
            }

            var networks3 = msfw.ListConnectedNetworkProfiles(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC);
            foreach (var network in networks3)
            {
                Console.WriteLine("Public:" + network);
            }

            }
            */
            //msfw.listAuditFailures();

        /*
        static bool isWinXP()
        {
           OperatingSystem os = Environment.OSVersion;
           int majorVersion = os.Version.Major;
           // see http://msdn.microsoft.com/en-us/library/ms724832(v=vs.85).aspx
           if (majorVersion < 6) // if O/S is not Vista or Windows7
           {
               return true;
           }
           else
           {
               return false;
           }
        }

        private static INetFwPolicy2 getCurrPolicy()
        {
            INetFwPolicy2 fwPolicy2;
            Type tNetFwPolicy2 = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(tNetFwPolicy2);
            return fwPolicy2;
        }

        static bool getFirewallStatus()
        {
            bool result = false;
            switch (isWinXP())
            {
                case true:
                    Type NetFwMgrType = Type.GetTypeFromProgID("HNetCfg.FwMgr", false); 
                    INetFwMgr mgr = (INetFwMgr)Activator.CreateInstance(NetFwMgrType);
                    result = mgr.LocalPolicy.CurrentProfile.FirewallEnabled;
                    break;
                case false:
                    INetFwPolicy2 fwPolicy2 = getCurrPolicy();
                    NET_FW_PROFILE_TYPE2_ fwCurrentProfileTypes;
                    //read Current Profile Types (only to increase Performace)
                    //avoids access on CurrentProfileTypes from each Property
                    fwCurrentProfileTypes = (NET_FW_PROFILE_TYPE2_)fwPolicy2.CurrentProfileTypes;
                    result = (fwPolicy2.get_FirewallEnabled(fwCurrentProfileTypes));
                    break;
                default:
                    Console.WriteLine("default");
                    result = false; // assume Win7 by default
                    break;
            }
            return result;
        }

        static void setFirewallStatus(bool newStatus)
        {
            switch (isWinXP())
            {
                case true:
                    Type NetFwMgrType = Type.GetTypeFromProgID("HNetCfg.FwMgr", false);
                    INetFwMgr mgr = (INetFwMgr)Activator.CreateInstance(NetFwMgrType);
                    mgr.LocalPolicy.CurrentProfile.FirewallEnabled = newStatus;
                    break;
                case false:
                    NET_FW_PROFILE_TYPE2_ fwCurrentProfileTypes;
                    INetFwPolicy2 currPolicy = getCurrPolicy();
                    //read Current Profile Types (only to increase Performace)
                    //avoids access on CurrentProfileTypes from each Property
                    fwCurrentProfileTypes = (NET_FW_PROFILE_TYPE2_)currPolicy.CurrentProfileTypes;
                    currPolicy.set_FirewallEnabled(fwCurrentProfileTypes, newStatus);
                    break;
                default:
                    NET_FW_PROFILE_TYPE2_ fwCurrentProfileTypes1;
                    INetFwPolicy2 currPolicy1 = getCurrPolicy();
                    //read Current Profile Types (only to increase Performace)
                    //avoids access on CurrentProfileTypes from each Property
                    fwCurrentProfileTypes1 = (NET_FW_PROFILE_TYPE2_)currPolicy1.CurrentProfileTypes;
                    currPolicy1.set_FirewallEnabled(fwCurrentProfileTypes1, newStatus);
                    break;
            }
        }
         */
    }
}