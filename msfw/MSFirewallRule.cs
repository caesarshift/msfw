using System;                     //default
using System.Collections.Generic; //dictionary,list
using System.Linq;                //because jon skeet
using NetFwTypeLib;               //firewall library
using System.Net.Sockets;         //protocol enum
using System.Net;                 //IPAddress class

namespace msfw
{
    /// <summary> 
    ///  Provides a wrapper around the INetFwRule2 class and adds support for "serializing" the
    ///  rule into the same format as what is stored in the registry for group policy firewall rules
    /// </summary> 
    public class MSFirewallRule
    {
        public INetFwRule2 rule;

        public NET_FW_ACTION_ Action { get { return this.rule.Action; } }
        public string ActionName { get { return MSFirewall.getActionName(this.rule.Action); } }
        public string ApplicationName { get { return this.rule.ApplicationName; } }
        public string AppAndService { get { return this.getAppAndService(); } }
        public NET_FW_RULE_DIRECTION_ Direction { get { return this.rule.Direction; } }
        public string DirectionName { get { return MSFirewall.getDirectionName(this.rule.Direction); } }
        public bool Enabled { get { return this.rule.Enabled; } }
        public string LocalAddresses { get { return this.getLocalAddresses(); } }
        public string LocalPorts { get { return this.rule.LocalPorts ?? "*"; } }
        public string Name { get { return this.rule.Name; } }
        public int Profiles { get { return this.rule.Profiles; } }
        public int Protocol { get { return this.rule.Protocol; } }
        public string ProtocolName { get { return Enum.GetName(typeof(ProtocolType), rule.Protocol) ?? "*"; } }
        public string RemoteAddresses { get { return this.getRemoteAddresses(); } }
        public string RemotePorts { get { return this.rule.RemotePorts ?? "*"; } }
        public string ServiceName { get { return this.rule.serviceName; } }
        public bool Extended { get { return this.isExtended(); } }

        /// <summary> 
        /// Constructor: takes in INetFwRule2.</summary> 
        public MSFirewallRule(INetFwRule2 rule)
        {
            this.rule = rule;
        }

        /// <summary>Constructor: Input is a "serialized" rule like one found in
        /// "Software\Policies\Microsoft\WindowsFirewall\FirewallRules".</summary>
        /// <remarks>See more details in the <see cref="parseRule"/> method</remarks>
        public MSFirewallRule(string rulestr)
            : this(rulestr, new Dictionary<string, string>())
        {
        }

        /// <summary> 
        /// Constructor: Input is a "serialized" fw rule string like one found in
        /// "Software\Policies\Microsoft\WindowsFirewall\FirewallRules"</summary>
        /// <remarks>Allows variable substitution for key/values by providing
        /// a dictionary of substitute information.
        /// This is necessary since the registry rules store name/description
        /// information in separate key/values.
        /// See more details in the <see cref="parseRule"/> method</remarks>
        public MSFirewallRule(string rulestr, Dictionary<string, string> info)
        {
            this.rule = this.parseRule(rulestr, info);
        }

        /// <summary>If rule contains attributes other than basic</summary>
        /// <remarks>Basic attribures are:
        /// 1. Action (Block, Allow)
        /// 2. Direction (In, Out)
        /// 3. Local IP Address/Port
        /// 4. Remote IP Address/Port
        /// 5. Application Name
        /// 6. Rule Name</remarks>
        private bool isExtended()
        {
            //basic
            bool extended = false;

            //if edge is false, then options is false
            //rule.EdgeTraversal;
            //rule.EdgeTraversalOptions;
            if (this.rule.EdgeTraversal)
            {
                //Console.WriteLine("Edge:TRUE");
                extended = true;
            }

            // "RemoteAccess", "Wireless", "Lan", and "All"
            if(rule.InterfaceTypes != "All")
            {
                //Console.WriteLine("InterfaceTypes not all");
                extended = true;
            }

            if (rule.Interfaces != null)
            {
                //Console.WriteLine("Interfaces not null");
                extended = true;
            }

            if (rule.IcmpTypesAndCodes != null)
            {
               // Console.WriteLine("Icmp types and codes not all");
                extended = true;
            }
            return extended;
        }

        /// <summary>Combines Application Name and Service Name</summary>
        private string getAppAndService()
        {
            var appname = "*";
            if (this.rule.ApplicationName != null)
            {
                appname = this.rule.ApplicationName;
                if (this.rule.serviceName != null)
                {
                    appname += ":" + this.rule.serviceName;
                }
            }
            return appname;
        }

        /// <summary>Returns IP address, removing subnet mask for individual IPs (IPv4)</summary>
        private string getLocalAddresses()
        {
            // TOOD: Support IPv6 LocalAddresses
            var laddress = rule.LocalAddresses;
            if (laddress.Contains("/255.255.255.255"))
            {
                laddress = laddress.Replace("/255.255.255.255", "");
            }
            return laddress ?? "*";
        }

        /// <summary>Returns IP address, removing subnet mask for individual IPs (IPv4)</summary>
        private string getRemoteAddresses()
        {
            // TOOD: Support IPv6 RemoteAddresses
            var raddress = rule.RemoteAddresses;
            if (raddress.Contains("/255.255.255.255"))
            {
                raddress = raddress.Replace("/255.255.255.255", "");
            }
            return raddress ?? "*";
        }

        /// <summary>Parses a rule str to make a INetFwRule2</summary>
        /// <remarks>This rule string is found in group policy rules and is undocumented,
        /// as far as I can tell. I've done my best to document my findings here.
        /// 
        /// Field                 : rule Mapping             : Values                : Example
        ///"Action"               : rule.Action              : Allow,Block           : Action=Allow
        ///"App"                  : rule.ApplicationName     : Text                  : App=onenote.exe
        ///"Desc"                 : rule.Description         : Text                  : Desc=My rule description
        ///"Dir"                  : rule.Direction           : In,Out                : Dir=In
        ///"Edge"                 : rule.EdgeTraversal       : Bool                  : Edge=TRUE
        ///"Defer"                : rule.EdgeTraversalOption : App,?                 : Defer=App
        ///"Active"               : rule.Enabled             : Bool                  : Active=TRUE
        ///"EmbedCtxt"            : rule.Grouping            : Text                  : EmbedCtxt=Core Networking
        ///"ICMP4","ICMP6"        : rule.IcmpTypesAndCodes   :                       : 
        ///?????????????????????  : rule.Interfaces          : ???                   : 
        ///?????????????????????  : rule.InterfaceTypes      : ???                   : 
        ///"LA4","LA6"            : rule.LocalAddresses      : IP(s) or Enum         : LA4=10.10.10.10 or LocalSubnet or ?
        ///"LPort","LPort2_10"    : rule.LocalPorts          : Port(s) or Enum       : LPort=4500 or ?
        ///"Name"                 : rule.Name                : Text                  : Name=My rule name
        ///"Profile"              : rule.Profiles            : Domain,Private,Public : Profile=Domain
        ///"Protocol"             : rule.Protocol            : ProtocolType          : Protocol=6
        ///"RA4", "RA6"           : rule.RemoteAddresses     : IP(s) or Enum         : RA4=10.10.10.10 or LocalSubnet or ?
        ///"RPort","RPort2_10"    : rule.RemotePorts         : Port(s) or Enum       : RPort=4500 or ?
        ///"Svc"                  : rule.serviceName         : Text                  : Svc=upnphost
        /// 
        /// Additional notes on fields:
        /// 
        /// All lists are comma-delimited
        /// If not present, booleans are FALSE and normally restrictive fields allow all
        /// "Action"    : required. Will be "Allow" or "Block"
        /// "App"       : optional. Will be a complete path to an executable. Will be a complete path to svchost.exe if using "Svc" field
        /// "Desc"      : optional. Variable substitution needed for rules from registry.
        /// "Dir"       : required. Will be "In" or "Out"
        /// "Edge"      : optional. Will be "TRUE". Default is "FALSE"
        /// "Defer"     : optional. See enum NET_FW_EDGE_TRAVERSAL_TYPE_ for values. Only appears if "Edge" is TRUE and only used for DEFER_TO_APP and DEFER_TO_USER
        /// "Active"    : required. Will be "TRUE" or "FALSE"
        /// "EmbedCtxt" : optional. Variable substitution needed for rules from registry.
        /// "ICMP4"     : optional. If Protocol is "Icmp", then list of allowed ICMP (v4) types and codes
        /// "ICMP6"     : optional. If Protocol is "IcmpV6", then list of allowed ICMP (v6) types and codes
        /// "LA4"       : optional. IPv4 Addresses (single, range, or subnet). Not allowed if "ICMP6" is defined.
        /// "LA6"       : optional. IPv6 Addresses (single, range, or subnet). Not allowed if "ICMP4" is defined.
        /// "LPort"     : optional. Port or port range.
        /// TODO: complete field documentation
        /// </remarks>
        public INetFwRule2 parseRule(string rulestr, Dictionary<string, string> info)
        {
            INetFwRule2 rule = (INetFwRule2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));

            string[] ruleAttribs = rulestr.Split('|');
            foreach (string ra in ruleAttribs)
            {
                var kv = ra.Split('=');
                switch (kv[0])
                {
                    case "":
                    case "v2.10":
                        //version ignore
                        break;
                    case "Action":
                        kv[1] = kv[1].ToLower();
                        if (kv[1] == "allow")
                        {
                            rule.Action = NET_FW_ACTION_.NET_FW_ACTION_ALLOW;
                        }
                        else if (kv[1] == "block")
                        {
                            rule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
                        }
                        else if (kv[1] == "max")
                        {
                            rule.Action = NET_FW_ACTION_.NET_FW_ACTION_MAX;
                        }
                        else
                        {
                            throw new Exception("parseRule: Unknown action in rule: " + kv[1]);
                        }
                        break;
                    case "Active":
                        kv[1] = kv[1].ToLower();
                        if (kv[1] == "true")
                        {
                            rule.Enabled = true;
                        }
                        else
                        {
                            rule.Enabled = false;
                        }
                        break;
                    case "App":
                        rule.ApplicationName = kv[1];
                        break;
                    case "Defer":
                        kv[1] = kv[1].ToLower();
                        if (kv[1] == "app")
                        {
                            rule.EdgeTraversalOptions = (int)NET_FW_EDGE_TRAVERSAL_TYPE_.NET_FW_EDGE_TRAVERSAL_TYPE_DEFER_TO_APP;
                        }
                        else
                        {
                            rule.EdgeTraversalOptions = (int)Enum.Parse(typeof(NET_FW_EDGE_TRAVERSAL_TYPE_), kv[1]);
                        }
                        break;
                    case "Desc":
                        if (info.ContainsKey(kv[1]))
                        {
                            rule.Description = info[kv[1]];
                        }
                        else
                        {
                            rule.Description = kv[1];
                        }
                        break;
                    case "Dir":
                        kv[1] = kv[1].ToLower();
                        if (kv[1] == "in")
                        {
                            rule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN;
                        }
                        else if (kv[1] == "out")
                        {
                            rule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT;
                        }
                        else if (kv[1] == "max")
                        {
                            rule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_MAX;
                        }
                        else
                        {
                            throw new Exception("parseRule: Unknown direction in rule: " + kv[1]);
                        }
                        break;
                    case "Edge":
                        kv[1] = kv[1].ToLower();
                        if (kv[1] == "true")
                        {
                            rule.EdgeTraversal = true;
                        }
                        else
                        {
                            rule.EdgeTraversal = false;
                        }
                        break;
                    case "EmbedCtxt":
                        if (info.ContainsKey(kv[1]))
                        {
                            rule.Grouping = info[kv[1]];
                        }
                        else
                        {
                            rule.Grouping = kv[1];
                        }
                        break;
                    case "ICMP4":
                    case "ICMP6":
                        if (rule.IcmpTypesAndCodes == "*")
                        {
                            rule.IcmpTypesAndCodes = kv[1];
                        }
                        else
                        {
                            //Console.WriteLine(rule.IcmpTypesAndCodes + " " + kv[1]);
                            rule.IcmpTypesAndCodes += "," + kv[1];
                        }
                        break;
                    case "LA4":
                    case "LA6":
                        if (rule.LocalAddresses == "*")
                        {
                            rule.LocalAddresses = kv[1];
                        }
                        else if (!rule.LocalAddresses.Contains(kv[1]))
                        {
                            rule.LocalAddresses += "," + kv[1];
                        }
                        break;
                    case "LPort":
                        if (rule.LocalPorts == "*")
                        {
                            //Console.WriteLine("init:" + kv[1]);
                            rule.LocalPorts = kv[1];
                        }
                        else
                        {
                            //Console.WriteLine("append: '" + rule.LocalPorts.ToString() + "'" + ":" + kv[1]);
                            rule.LocalPorts = rule.LocalPorts.ToString() + "," + kv[1];
                        }
                        break;
                    case "LPort2_10":
                        //todo:IPHTTPS maps to IPHTTPSIn AND IPTLSIn
                        //warning: unknown if correct; no example yet
                        rule.LocalPorts = kv[1];
                        break;
                    case "Name":
                        if (info.ContainsKey(kv[1]))
                        {
                            rule.Name = info[kv[1]];
                        }
                        else
                        {
                            rule.Name = kv[1];
                        }
                        break;
                    case "Profile":
                        if (rule.Profiles == (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_ALL)
                        {
                            switch (kv[1])
                            {
                                case "Domain":
                                    rule.Profiles = (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN;
                                    break;
                                case "Private":
                                    rule.Profiles = (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE;
                                    break;
                                case "Public":
                                    rule.Profiles = (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC;
                                    break;
                            }
                        }
                        else
                        {
                            switch (kv[1])
                            {
                                case "Domain":
                                    rule.Profiles = rule.Profiles | (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN;
                                    break;
                                case "Private":
                                    rule.Profiles = rule.Profiles | (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE;
                                    break;
                                case "Public":
                                    rule.Profiles = rule.Profiles | (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC;
                                    break;
                            }
                        }
                        break;
                    case "Protocol":
                        rule.Protocol = Int32.Parse(kv[1]);
                        break;
                    case "RA4":
                    case "RA6":
                        if (rule.RemoteAddresses == "*")
                        {
                            rule.RemoteAddresses = kv[1];
                        }
                        else if (!rule.RemoteAddresses.Contains(kv[1]))
                        {
                            rule.RemoteAddresses += "," + kv[1];
                        }
                        //Console.WriteLine(rule.RemoteAddresses + " + " + kv[1]);
                        //Console.WriteLine(rule.RemoteAddresses);
                        break;
                    case "RPort":
                        if (rule.RemotePorts == "*")
                        {
                            //Console.WriteLine("init:" + kv[1]);
                            rule.RemotePorts = kv[1];
                        }
                        else
                        {
                            //Console.WriteLine("append: '" + rule.RemotePorts.ToString() + "'" + ":" + kv[1]);
                            rule.RemotePorts += "," + kv[1];
                        }
                        break;
                    case "RPort2_10":
                        //does IPHTTPS maps to IPHTTPSOut AND IPTLSOut ????
                        //warning: unknown if correct; no example yet
                        rule.RemotePorts = kv[1];
                        break;
                    case "Svc":
                        rule.serviceName = kv[1];
                        break;
                    default:
                        throw new Exception("Uknown firewall rule type:" + kv[0]);
                }
            }
            if (((rule.Profiles & (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN) == (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN) &&
                ((rule.Profiles & (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE) == (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE) &&
                ((rule.Profiles & (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC) == (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC)
               )
            {
                rule.Profiles = (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_ALL;
            }

            return rule;
        }

        /// <summary>Returns the rule as a string using the same format as the group policy rules that are found in the registry</summary>
        public override string ToString()
        {
            //todo: rule.Interfaces
            //todo: rule.InterfaceTypes
            INetFwRule2 rule = this.rule;

            string rs = "v2.10";

            var aorder = new List<string> { "Action", "Active", "Dir", "Protocol", "Profile", "ICMP4", "ICMP6", "LPort", "LPort2_10", "RPort", "RPort2_10", "LA4", "LA6", "RA4", "RA6", "App", "Svc", "Name", "Desc", "EmbedCtxt", "Edge", "Defer" };
            var attributes = new Dictionary<string, List<string>>();
            var strAddresses = new List<string> { "LocalSubnet", "DHCP", "DNS", "WINS", "DefaultGateway" };
            IPAddress address;
            var curA = "";

            //required: if not present then "All"
            curA = "Profile";
            var fwProfiles = Enum.GetValues(typeof(NET_FW_PROFILE_TYPE2_));
            foreach (NET_FW_PROFILE_TYPE2_ fwProfile in fwProfiles)
            {
                if (((NET_FW_PROFILE_TYPE2_)rule.Profiles & fwProfile) == fwProfile)
                {
                    if (!attributes.ContainsKey(curA))
                        attributes.Add(curA, new List<string>());
                    attributes[curA].Add(curA + "=" + MSFirewall.getProfileName(fwProfile));
                }
            }
            if ((NET_FW_PROFILE_TYPE2_)rule.Profiles == NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_ALL)
            {
                attributes.Remove(curA);
            }

            //optional
            if (rule.Grouping != null)
            {
                curA = "EmbedCtxt";
                attributes.Add(curA, new List<string> { curA + "=" + rule.Grouping });
            }

            //required
            curA = "Name";
            attributes.Add(curA, new List<string> { curA + "=" + rule.Name });

            //required
            curA = "Action";
            attributes.Add(curA, new List<string> { curA + "=" + MSFirewall.getActionName(rule.Action) });

            //optional
            if (rule.Description != null)
            {
                curA = "Desc";
                attributes.Add(curA, new List<string> { curA + "=" + rule.Description });
            }

            //required
            curA = "Dir";
            attributes.Add(curA, new List<string> { curA + "=" + MSFirewall.getDirectionName(rule.Direction) });

            if (rule.ApplicationName != null)
            {
                curA = "App";
                if (!attributes.ContainsKey(curA))
                    attributes.Add(curA, new List<string>());
                attributes[curA].Add(curA + "=" + rule.ApplicationName);
            }

            if (rule.serviceName != null)
            {
                curA = "Svc";
                if (!attributes.ContainsKey(curA))
                    attributes.Add(curA, new List<string>());
                attributes[curA].Add(curA + "=" + rule.serviceName);
            }

            if (rule.LocalPorts != "*" && rule.LocalPorts != null)
            {
                foreach (string r in rule.LocalPorts.Split(','))
                {
                    if (r == "IPHTTPS")
                    {
                        curA = "LPort2_10";
                        if (rule.Direction == NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN)
                        {
                            attributes.Add(curA, new List<string>());
                            attributes[curA].Add(curA + "=IPTLSIn");
                            attributes[curA].Add(curA + "=IPHTTPSIn");
                        }
                        else
                        {
                            attributes.Add(curA, new List<string>());
                            attributes[curA].Add(curA + "=IPTLSOut");
                            attributes[curA].Add(curA + "=IPHTTPSOut");
                        }
                    }
                    else
                    {
                        curA = "LPort";
                        if (!attributes.ContainsKey(curA))
                            attributes.Add(curA, new List<string>());
                        attributes[curA].Add(curA + "=" + r);
                    }
                }
            }

            if (rule.LocalAddresses != null && rule.LocalAddresses != "*")
            {
                var ra = rule.LocalAddresses.Split(',');
                foreach (string r in ra)
                {
                    curA = "";
                    if (strAddresses.Contains(r))
                    {
                        curA = "LA4,LA6";
                    }
                    else if (IPAddress.TryParse(r, out address))
                    {
                        switch (address.AddressFamily)
                        {
                            case System.Net.Sockets.AddressFamily.InterNetwork:
                                curA = "LA4";
                                break;
                            case System.Net.Sockets.AddressFamily.InterNetworkV6:
                                curA = "LA6";
                                break;
                            default:
                                throw new Exception("Unknown remote address: {0}" + r);
                        }
                    }
                    else if (r.Contains(':'))
                    {
                        curA = "LA6";
                    }
                    else
                    {
                        curA = "LA4";
                    }

                    if (curA != "")
                    {
                        foreach (string a in curA.Split(','))
                        {
                            if (!attributes.ContainsKey(a))
                                attributes.Add(a, new List<string>());

                            var sub = false;
                            if (r.Contains('-'))
                            {
                                var rtest = r.Split('-');
                                if (rtest[0] == rtest[1])
                                {
                                    attributes[a].Add(a + "=" + rtest[0]);
                                    sub = true;
                                }
                            }
                            else if (r.Contains("/255.255.255.255"))
                            {
                                var rtest = r.Split('/');
                                attributes[a].Add(a + "=" + rtest[0]);
                                sub = true;
                            }

                            if (!sub)
                            {
                                attributes[a].Add(a + "=" + r);
                            }
                        }
                    }
                }
            }

            if (rule.RemotePorts != "*" && rule.RemotePorts != null)
            {
                foreach (string r in rule.RemotePorts.Split(','))
                {
                    if (r == "IPHTTPS")
                    {
                        curA = "RPort2_10";
                        if (rule.Direction == NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN)
                        {
                            attributes.Add(curA, new List<string>());
                            attributes[curA].Add(curA + "=IPTLSIn");
                            attributes[curA].Add(curA + "=IPHTTPSIn");
                        }
                        else
                        {
                            attributes.Add(curA, new List<string>());
                            attributes[curA].Add(curA + "=IPTLSOut");
                            attributes[curA].Add(curA + "=IPHTTPSOut");
                        }
                    }
                    else
                    {
                        curA = "RPort";
                        if (!attributes.ContainsKey(curA))
                            attributes.Add(curA, new List<string>());
                        attributes[curA].Add(curA + "=" + r);
                    }
                }
            }

            //if any, not present
            if (rule.RemoteAddresses != null && rule.RemoteAddresses != "*")
            {
                var ra = rule.RemoteAddresses.Split(',');
                foreach (string r in ra)
                {
                    curA = "";
                    if (strAddresses.Contains(r))
                    {
                        curA = "RA4,RA6";
                    }
                    else if (IPAddress.TryParse(r, out address))
                    {
                        switch (address.AddressFamily)
                        {
                            case System.Net.Sockets.AddressFamily.InterNetwork:
                                curA = "RA4";
                                break;
                            case System.Net.Sockets.AddressFamily.InterNetworkV6:
                                curA = "RA6";
                                break;
                            default:
                                throw new Exception("Unknown remote address: {0}" + r);
                        }
                    }
                    else if (r.Contains(':'))
                    {
                        curA = "RA6";
                    }
                    else
                    {
                        curA = "RA4";
                    }

                    if (curA != "")
                    {
                        foreach (string a in curA.Split(','))
                        {
                            if (!attributes.ContainsKey(a))
                                attributes.Add(a, new List<string>());

                            var sub = false;
                            if (r.Contains('-'))
                            {
                                var rtest = r.Split('-');
                                if (rtest[0] == rtest[1])
                                {
                                    attributes[a].Add(a + "=" + rtest[0]);
                                    sub = true;
                                }
                            }
                            else if (r.Contains("/255.255.255.255"))
                            {
                                var rtest = r.Split('/');
                                attributes[a].Add(a + "=" + rtest[0]);
                                sub = true;
                            }

                            if (!sub)
                            {
                                attributes[a].Add(a + "=" + r);
                            }
                        }
                    }
                }
            }

            //if any, then no setting
            if (rule.Protocol != 256) //any
            {
                curA = "Protocol";
                if (!attributes.ContainsKey(curA))
                    attributes.Add(curA, new List<string>());
                attributes[curA].Add(curA + "=" + rule.Protocol);
            }

            //required
            curA = "Active";
            if (rule.Enabled)
                attributes.Add(curA, new List<string> { curA + "=TRUE" });
            else
                attributes.Add(curA, new List<string> { curA + "=FALSE" });

            //if not present, then false
            if (rule.EdgeTraversal)
            {
                curA = "Edge";
                attributes.Add(curA, new List<string> { curA + "=TRUE" });
            }

            //if any, then no setting
            curA = "Defer";
            if (rule.EdgeTraversalOptions > 0)
            {
                if (rule.EdgeTraversalOptions == (int)NET_FW_EDGE_TRAVERSAL_TYPE_.NET_FW_EDGE_TRAVERSAL_TYPE_DEFER_TO_APP)
                {
                    if (!attributes.ContainsKey(curA))
                        attributes.Add(curA, new List<string>());
                    attributes[curA].Add(curA + "=App");
                }
                else if (rule.EdgeTraversalOptions == (int)NET_FW_EDGE_TRAVERSAL_TYPE_.NET_FW_EDGE_TRAVERSAL_TYPE_ALLOW)
                {
                    //do nothing because rule.EdgeTraversal should be set to true already
                }
                else
                {
                    if (!attributes.ContainsKey(curA))
                        attributes.Add(curA, new List<string>());
                    attributes[curA].Add(curA + "=" + rule.EdgeTraversalOptions);
                }
            }

            if (rule.IcmpTypesAndCodes != null)
            {
                if (rule.Protocol == 1)
                {
                    curA = "ICMP4";
                }
                else if (rule.Protocol == 58)
                {
                    curA = "ICMP6";
                }
                if (!attributes.ContainsKey(curA))
                    attributes.Add(curA, new List<string>());
                attributes[curA].Add(curA + "=" + rule.IcmpTypesAndCodes);
            }

            //ICMPv6 shouldn't have v4 local addresses and vice versa
            // TODO: add 41,43,44,59,60 (test first)
            if (rule.Protocol == 58 && attributes.ContainsKey("LA4"))
            {
                attributes.Remove("LA4");
            }
            else if (rule.Protocol == 1 && attributes.ContainsKey("LA6"))
            {
                attributes.Remove("LA6");
            }

            //ICMPv6 shouldn't have v4 remote addresses and vice versa
            // TODO: add 41,43,44,59,60 (test first)
            if (rule.Protocol == 58 && attributes.ContainsKey("RA4"))
            {
                attributes.Remove("RA4");
            }
            else if (rule.Protocol == 1 && attributes.ContainsKey("RA6"))
            {
                attributes.Remove("RA6");
            }

            //preserve order of keys
            foreach (var a in aorder)
            {
                if (attributes.ContainsKey(a))
                {
                    rs = rs + "|" + String.Join("|", attributes[a]);
                }
            }
            rs = rs + "|";
            return rs;
        }
    }
}