using System;                             //default
using System.Collections.Generic;         //lists
using System.ServiceProcess;              //service state
using NetFwTypeLib;                       //firewall library
using Microsoft.Win32;                    //registry access
using Microsoft.WindowsAPICodePack.Net;   //network connections
using System.Diagnostics;                 //auditing and process
using System.Linq;                        //auditing
using System.Diagnostics.Eventing.Reader; //auditing
using System.IO;                          //file name path
using System.Net.Sockets;                 //protocol enum
using System.Threading;                   //sleep
using System.Net.NetworkInformation;      //network interfaces
using NLog;                               //logging
//todo: support windows xp
//todo: add debug logging

namespace msfw
{
    /* I can't find this defined in the NetFwTypeLib */
    enum NET_FW_EDGE_TRAVERSAL_TYPE_
    {
        NET_FW_EDGE_TRAVERSAL_TYPE_DENY          = 0,
        NET_FW_EDGE_TRAVERSAL_TYPE_ALLOW         = 1,
        NET_FW_EDGE_TRAVERSAL_TYPE_DEFER_TO_APP  = 2,
        NET_FW_EDGE_TRAVERSAL_TYPE_DEFER_TO_USER = 3
    }

    class MSFirewall
    {
        const string hkeyRoot   = "HKEY_LOCAL_MACHINE";
        const string domainkey  = "Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile";
        const string privatekey = "Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile";
        const string publickey  = "Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile";
        const string ruleskey   = "Software\\Policies\\Microsoft\\WindowsFirewall\\FirewallRules";
        const string infokey    = "Local Settings\\MuiCache"; //strings used in group policy fw rules (name, desc, etc.)

        public Dictionary<NET_FW_PROFILE_TYPE2_, string> fwRegKey; // settings lookup per fw profile
        public INetFwPolicy2 fw; //fw class instance
        public NET_FW_PROFILE_TYPE2_ currentFwProfile; //current profile; cache current setting to avoid lookup every call

        private static Logger logger = LogManager.GetCurrentClassLogger();

        public MSFirewall()
        {
            //load fw by path
            //using it for rainmeter testing
            //Assembly assembly = Assembly.LoadFrom(@"D:\\Program Files\\Rainmeter\\Plugins\\Interop.NetFwTypeLib.dll");
            //Type tNetFwPolicy2 = assembly.GetType("HNetCfg.FwPolicy2");

            Type tNetFwPolicy2 = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            fw = (INetFwPolicy2)Activator.CreateInstance(tNetFwPolicy2);

            if (fw == null)
            {
                string state = getServiceState();
                if (state == "Running") {
                    throw new Exception("Unable to create firewall class due to an unknown error");
                } else {
                    throw new Exception("Windows Firewall Service is not running. Please start the service and try again");
                }
            }

            updateCurrentProfile();

            fwRegKey = new Dictionary<NET_FW_PROFILE_TYPE2_, string>();
            fwRegKey.Add(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN, domainkey);
            fwRegKey.Add(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE, privatekey);
            fwRegKey.Add(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC, publickey);            
        }

        /* List all local rules */
        public List<MSFirewallRule> getLocalRules(bool enabledOnly = false) {
            List<MSFirewallRule> fwLocalRules = new List<MSFirewallRule>();
            foreach (INetFwRule2 rule in fw.Rules)
            {
                logger.Debug("Local firewall rule: {0}={1}", rule.Name, rule.Enabled);
                if (!enabledOnly || (enabledOnly && rule.Enabled))
                {
                    fwLocalRules.Add(new MSFirewallRule(rule));
                }
            }
            return fwLocalRules;
        }

        public Dictionary<string, string> getPolicyInfo()
        {
            //ugly way of getting these values:
            //infokey\UNKNOWN\UNKNOWN2\@FirewallAPI.dll strings
            var policyinfo = new Dictionary<string, string>();

            RegistryKey infoparent = Registry.ClassesRoot.OpenSubKey(infokey);

            if(infoparent != null) {
                foreach (string csub in infoparent.GetSubKeyNames())
                {
                    RegistryKey infochild = infoparent.OpenSubKey(csub);
                    if(infochild != null) {
                        foreach (string gcsub in infochild.GetSubKeyNames())
                        {
                            RegistryKey infograndchild = infochild.OpenSubKey(gcsub);
                            if(infograndchild != null)
                            {
                                foreach (string fwInfo in infograndchild.GetValueNames())
                                {
                                    //@FirewallAPI.dll,-25408
                                    //@%systemroot%\system32\provsvc.dll,-200
                                    //@snmptrap.exe,-7
                                    logger.Debug("Policy info: {0}={1}", fwInfo, infograndchild.GetValue(fwInfo).ToString());
                                    policyinfo.Add(fwInfo, infograndchild.GetValue(fwInfo).ToString());
                                }
                            }
                            else
                            {
                                logger.Warn("Policy info registry key ({0}) is null", gcsub);
                            }
                        }
                    }
                    else
                    {
                        logger.Warn("Policy info registry key ({0}) is null", csub);
                    }
                }
            }
            else
            {
                logger.Warn("Policy info registry key ({0}) is null", infokey);
            }

            return policyinfo;
        }

        public List<MSFirewallRule> getPolicyRules()
        {
            List<MSFirewallRule> fwPolicyRules = new List<MSFirewallRule>();

            var info = getPolicyInfo();

            RegistryKey policyrules = Registry.LocalMachine.OpenSubKey(ruleskey);
            foreach(string valueName in policyrules.GetValueNames())
            {
                logger.Debug("Found policy rule: {0}", policyrules.GetValue(valueName).ToString());
                fwPolicyRules.Add(new MSFirewallRule(policyrules.GetValue(valueName).ToString(), info));
            }

            return fwPolicyRules;
        }

        public List<MSFirewallRule> getLocalRulesByName(string rulename, bool enabledOnly = true)
        {
            var retRules = new List<MSFirewallRule>();
            List<MSFirewallRule> localRules = getLocalRules();
            foreach (MSFirewallRule rule in localRules)
            {
                if (rule.Name.ToLower() == rulename.ToLower())
                {
                    if (!enabledOnly || (enabledOnly && rule.Enabled))
                    {
                        retRules.Add(rule);
                    }
                }
            }
            return retRules;
        }

        public int countLocalRules(string rulename, bool enabledOnly = true)
        {
            var rules = getLocalRulesByName(rulename, enabledOnly);
            return rules.Count;
        }

        public int deleteLocalRule(string rulename, bool enabledOnly = true)
        {
            var delRulesCnt = 0;
            var delRules = getLocalRulesByName(rulename, enabledOnly);

            foreach (MSFirewallRule rule in delRules)
            {
                logger.Debug("Delete rule: rule.Name");
                fw.Rules.Remove(rule.Name);
                delRulesCnt++;
            }

            return delRulesCnt;
        }

        /* delete all group policy disabled rules */
        /* warning: if these are actively being set via GPO, they will come back */
        /*
        public int deletedDisabledPolicyRules() {
            var delRulesCnt = 0;
            var delRules = new List<string>();

            RegistryKey policyrules = Registry.LocalMachine.OpenSubKey(ruleskey);
            foreach(string valueName in policyrules.GetValueNames())
            {
                if (!policyrules.GetValue(valueName).ToString().Contains("Active=TRUE"))
                {
                    //delRules.Add("Test");
                }
            }

            foreach (string rule in delRules)
            {
                //fw.Rules.Remove(rule);
                //delRulesCnt++;
            }

            return delRulesCnt;
        }
        */

        public void addRule(INetFwRule2 rule)
        {
            fw.Rules.Add(rule);
        }

        /* delete all local disabled rules */
        public int deleteDisabledLocalRules() {
            var delRulesCnt = 0;
            var delRules = new List<INetFwRule2>();

            foreach (INetFwRule2 rule in fw.Rules)
            {
                if (!rule.Enabled)
                {
                    delRules.Add(rule);
                }
            }

            foreach (INetFwRule2 rule in delRules)
            {
                fw.Rules.Remove(rule.Name);
                delRulesCnt++;
            }
            return delRulesCnt;
        }

        public void updateCurrentProfile()
        {
            try
            {
                currentFwProfile = (NET_FW_PROFILE_TYPE2_)fw.CurrentProfileTypes;
            }
            catch (Exception)
            {
                this.fw = null;
                currentFwProfile = 0x0;
            }
        }

        public Dictionary<string, List<string>> NetworksByProfileDict(NET_FW_PROFILE_TYPE2_ profile, NetworkConnectivityLevels level = NetworkConnectivityLevels.All)
        {
            var networks = new Dictionary<string, List<string>>();

            //populate interface lookup
            var adapterLookup = new Dictionary<string, string>();
            NetworkInterface[] adapters = NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface adapter in adapters)
            {
                //from:{E46DFF2D-EB92-4A84-A0D3-01DDD2DC041E}
                //  to: e46dff2d-eb92-4a84-a0d3-01ddd2dc041e
                logger.Debug("Adapter: {0}={1}", adapter.Id.ToLower().Replace("{", "").Replace("}", ""), adapter.Name);
                adapterLookup.Add(adapter.Id.ToLower().Replace("{", "").Replace("}", ""), adapter.Name);
            }

            NetworkCategory profileName = NetworkCategory.Public;

            switch (profile)
            {
                case NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN:
                    profileName = NetworkCategory.Authenticated;
                    break;
                case NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE:
                    profileName = NetworkCategory.Private;
                    break;
                case NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC:
                    profileName = NetworkCategory.Public;
                    break;
            }
            /*
            NetworkCollection nCollection2 = NetworkListManager.GetNetworks(NetworkConnectivityLevels.All);
            foreach (Network net in nCollection2)
            {
                if (net.IsConnected || net.IsConnectedToInternet)
                {
                    Console.WriteLine(String.Format("CONNECTED: {0} {1} {2} {3}", net.Name, net.Category, net.DomainType, net.IsConnectedToInternet));
                }
                else
                {
                    Console.WriteLine(String.Format("Not connected: {0} {1} {2} {3}", net.Name, net.Category, net.DomainType, net.IsConnectedToInternet));
                }
            }
            */

            //Install-Package WindowsAPICodePack-Core
            NetworkCollection nCollection = NetworkListManager.GetNetworks(level);
            foreach (Network net in nCollection)
            {
                logger.Debug("Network: {0}={1}", net.Name, net.Category);
                if (net.Category == profileName)
                {
                    var netAdapters = new List<string>();
                    var conns = net.Connections;
                    if (conns.Count() == 0)
                    {
                        logger.Debug("No active connections for network");
                    }
                    foreach (var c in conns)
                    {
                        if (adapterLookup.ContainsKey(c.AdapterId.ToString()))
                        {
                            logger.Debug("Found adapter: {0}", adapterLookup[c.AdapterId.ToString()]);
                            netAdapters.Add(adapterLookup[c.AdapterId.ToString()]);
                        }
                        else
                        {
                            logger.Debug("Unknown adapter: {0}", c.AdapterId.ToString());
                            netAdapters.Add("Unknown");
                        }
                    }

                    networks.Add(net.Name, new List<string>());
                    foreach (var na in netAdapters)
                    {
                        networks[net.Name].Add(na);
                    }
                }
            }
            return networks;
        }

        public List<string> getInterfaces()
        {
            var interfaces = new List<string>();
            NetworkInterface[] adapters = NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface adapter in adapters)
            {
                interfaces.Add(adapter.Name);
            }
            return interfaces;
        }

        public int addExcludedInterface(NET_FW_PROFILE_TYPE2_ fwProfile, string exint)
        {
            //0 == success
            //1 == interface not found
            int ret = 0;

            var interfaces = getInterfaces();

            var i = interfaces.FindIndex(x => x.Equals(exint, StringComparison.OrdinalIgnoreCase));

            if (i == -1)
            {
                ret = 1;
            }

            //make case correct
            exint = interfaces[i];

            var ex = getExcludedInterfaces(fwProfile);

            if (!ex.ContainsKey(exint))
            {
                ex.Add(exint, 0);
                setExcludedInterfaces(fwProfile, ex.Keys.ToList());
            }

            return ret;
        }

        public int addIncludedInterface(NET_FW_PROFILE_TYPE2_ fwProfile, string addint)
        {
            //0 == success
            //1 == interface not excluded

            int ret = 0;

            //remember: by "including an interface," we are *removing* it from
            //the excluded interface list
            var ex = getExcludedInterfaces(fwProfile);
            var exlist = ex.Keys.ToList();
            var i = exlist.FindIndex(x => x.Equals(addint, StringComparison.OrdinalIgnoreCase));

            if (i == -1)
            {
                ret = 1;
            }
            else
            {
                exlist.Remove(exlist[i]);
                setExcludedInterfaces(fwProfile, exlist);
            }

            return ret;
        }

        public void setExcludedInterfaces(NET_FW_PROFILE_TYPE2_ fwProfile, List<string> excluded)
        {
            var objExcluded = new object[excluded.Count];
            for (var i = 0; i < excluded.Count; ++i)
            {
                objExcluded[i] = excluded[i].ToString();
            }

            if (excluded.Count == 0)
            {
                fw.set_ExcludedInterfaces(fwProfile, null);
            }
            else
            {
                fw.set_ExcludedInterfaces(fwProfile, objExcluded);
            }
        }

        /* Lists connected networks by profile */
        public List<string> NetworksByProfileList(NET_FW_PROFILE_TYPE2_ profile, NetworkConnectivityLevels level = NetworkConnectivityLevels.All)
        {
            List<string> networks = new List<string>();
            NetworkCategory profileName = NetworkCategory.Public;

            switch (profile)
            {
                case NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN:
                    profileName = NetworkCategory.Authenticated;
                    break;
                case NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE:
                    profileName = NetworkCategory.Private;
                    break;
                case NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC:
                    profileName = NetworkCategory.Public;
                    break;
            }

            //Install-Package WindowsAPICodePack-Core
            NetworkCollection nCollection = NetworkListManager.GetNetworks(level);
            foreach (Network net in nCollection)
            {
                if (net.Category == profileName)
                {
                    networks.Add(net.Name);
                }
            }
            return networks;
        }

        /* Get Windows Service State */
        public string getServiceState()
        {
            ServiceController sc = new ServiceController("Windows Firewall");
            string serviceState = "Unknown";
            switch (sc.Status)
            {
                case ServiceControllerStatus.Running:
                    serviceState = "Running";
                    break;
                case ServiceControllerStatus.Stopped:
                    serviceState = "Stopped";
                    break;
                case ServiceControllerStatus.Paused:
                    serviceState = "Paused";
                    break;
                case ServiceControllerStatus.StopPending:
                    serviceState = "Stopping";
                    break;
                case ServiceControllerStatus.StartPending:
                    serviceState = "Starting";
                    break;
            }
            return serviceState;
        }

        /* Checks local and policy setting for enabled firewall by profile */
        public Boolean isEnabled(NET_FW_PROFILE_TYPE2_ fwProfile, bool updateProfile = true)
        {
            var enabled = false;

            if(updateProfile)
                updateCurrentProfile();

            //something went wrong; abort and say not enabled
            if (fw == null)
            {
                return enabled;
            }

            if (fw.get_FirewallEnabled(fwProfile))
            {
                enabled = true;
            }

            //check GPO
            if (!enabled)
            {
                enabled = Convert.ToBoolean(Registry.GetValue(hkeyRoot + "\\" + fwRegKey[fwProfile], "EnableFirewall", false));
            }
            return enabled;
        }

        public void setExcludedInterfaces(NET_FW_PROFILE_TYPE2_ fwProfile, object interfaces)
        {
            fw.set_ExcludedInterfaces(fwProfile, interfaces);
        }

        public Dictionary<string,int> getExcludedInterfaces(NET_FW_PROFILE_TYPE2_ fwProfile)
        {
            var excluded = new Dictionary<string, int>();
            var intex = fw.get_ExcludedInterfaces(fwProfile);
            if (intex != null)
            {
                foreach (string ex in intex)
                {
                    excluded.Add(ex, 0);
                }
            }
            return excluded;
        }

        public Boolean setInboundAction(NET_FW_PROFILE_TYPE2_ fwProfile, NET_FW_ACTION_ action)
        {
            fw.set_DefaultInboundAction(fwProfile, action);
            return true;
        }

        public Boolean setOutboundAction(NET_FW_PROFILE_TYPE2_ fwProfile, NET_FW_ACTION_ action)
        {
            fw.set_DefaultOutboundAction(fwProfile, action);
            return true;
        }

        public Boolean Enable(NET_FW_PROFILE_TYPE2_ fwProfile)
        {
            return changeStatus(fwProfile, true);
        }

        public Boolean Disable(NET_FW_PROFILE_TYPE2_ fwProfile)
        {
            return changeStatus(fwProfile, false);
        }

        private Boolean changeStatus(NET_FW_PROFILE_TYPE2_ fwProfile, Boolean enabled)
        {
            fw.set_FirewallEnabled(fwProfile, enabled);
            return true;
        }

        public string isActiveStr(NET_FW_PROFILE_TYPE2_ fwProfile, bool updateProfile = true)
        {
            return (isActive(fwProfile, updateProfile)) ? "Active" : "Inactive";
        }

        public string isEnabledStr(NET_FW_PROFILE_TYPE2_ fwProfile, bool updateProfile = true)
        {
            return (isEnabled(fwProfile, updateProfile)) ? "Enabled" : "Disabled";
        }

        /* Checks if firewall is enabled and is actively enforced on a network connection */
        public Boolean isActive(NET_FW_PROFILE_TYPE2_ fwProfile, bool updateProfile = true)
        {
            var active = false;

            if (updateProfile)
                updateCurrentProfile();

            if ((this.currentFwProfile & fwProfile) == fwProfile)
            {
                active = isEnabled(fwProfile);
            }

            return active;
        }

        /* Returns default inbound action (Block|Allow) for profile */
        public String getCurInboundAction(NET_FW_PROFILE_TYPE2_ profile)
        {
            var curAction = "None";
            var curActions = new List<string>();
            var tmpstr = "";
            var fwProfiles = Enum.GetValues(typeof(NET_FW_PROFILE_TYPE2_));
            updateCurrentProfile();
            foreach (NET_FW_PROFILE_TYPE2_ fwProfile in fwProfiles)
            {
                if ((profile & fwProfile) == fwProfile)
                {
                    tmpstr = getActionName(fw.get_DefaultInboundAction(fwProfile));
                    if (fw.get_BlockAllInboundTraffic(fwProfile) == true)
                    {
                        tmpstr = tmpstr + " (All)";
                    }
                    curActions.Add(tmpstr);
                }
            }

            if (curActions.Count > 0)
            {
                curAction = String.Join(",", curActions);
            }
            return curAction;
        }

        /* Returns default outbound action (Block|Allow) for profile */
        public String getCurOutboundAction(NET_FW_PROFILE_TYPE2_ profile)
        {
            var curAction = "None";
            var curActions = new List<string>();
            var fwProfiles = Enum.GetValues(typeof(NET_FW_PROFILE_TYPE2_));
            updateCurrentProfile();
            foreach (NET_FW_PROFILE_TYPE2_ fwProfile in fwProfiles)
            {
                if ((profile & fwProfile) == fwProfile)
                {
                    curActions.Add(getActionName(fw.get_DefaultOutboundAction(fwProfile)));
                }
            }

            if (curActions.Count > 0)
            {
                curAction = String.Join(",", curActions);
            }
            return curAction;
        }

        /* Returns comma-delimited list of active profiles */
        public String getCurProfileName()
        {
            var curProfile = "None";
            var curProfiles = new List<string>();
            var fwProfiles = Enum.GetValues(typeof(NET_FW_PROFILE_TYPE2_));
            updateCurrentProfile();
            foreach (NET_FW_PROFILE_TYPE2_ fwProfile in fwProfiles)
            {
                if ((this.currentFwProfile & fwProfile) == fwProfile)
                {
                    curProfiles.Add(getProfileName(fwProfile));
                }
            }

            if (curProfiles.Count > 0) {
                curProfile = String.Join(",", curProfiles);
            }
            return curProfile;
        }

        /* Returns fixed-width list of profile names */
        static public String getProfileNamesAbbrev(NET_FW_PROFILE_TYPE2_ curFwProfiles)
        {
            var curProfile = "--,--,--";
            var curProfiles = new List<string>();
            var fwProfiles = Enum.GetValues(typeof(NET_FW_PROFILE_TYPE2_));
            foreach (NET_FW_PROFILE_TYPE2_ fwProfile in fwProfiles)
            {
                if (getProfileName(fwProfile) == "All")
                {
                    continue;
                }

                if ((curFwProfiles & fwProfile) == fwProfile)
                {
                    curProfiles.Add(getProfileName(fwProfile).Substring(0,2));
                }
                else
                {
                    curProfiles.Add("--");
                }
            }

            if (curProfiles.Count > 0)
            {
                curProfile = String.Join(",", curProfiles);
            }

            return curProfile;
        }

        /* Returns comma-delimited list of profile names */
        static public String getProfileNames(NET_FW_PROFILE_TYPE2_ curFwProfiles)
        {
            var curProfile = "None";
            var curProfiles = new List<string>();
            var fwProfiles = Enum.GetValues(typeof(NET_FW_PROFILE_TYPE2_));
            foreach (NET_FW_PROFILE_TYPE2_ fwProfile in fwProfiles)
            {
                if ((curFwProfiles & fwProfile) == fwProfile)
                {
                    curProfiles.Add(getProfileName(fwProfile));
                }
            }

            if (curProfiles.Count > 0)
            {
                curProfile = String.Join(",", curProfiles);
            }

            if (curProfile.Contains("All"))
            {
                curProfile = "All";
            }
            return curProfile;
        }

        /* Returns name of profile */
        static public String getProfileName(NET_FW_PROFILE_TYPE2_ profileEnum)
        {
            String fwProfileName = "";
            switch (profileEnum)
            {
                case NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_ALL:
                    fwProfileName = "All";
                    break;
                case NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN:
                    fwProfileName = "Domain";
                    break;
                case NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE:
                    fwProfileName = "Private";
                    break;
                case NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC:
                    fwProfileName = "Public";
                    break;
                default:
                    fwProfileName = "Unknown";
                    break;
            }
            return fwProfileName;
        }

        /* Returns action name */
        //Todo: What is Max?
        static public String getActionName(NET_FW_ACTION_ actionEnum)
        {
            String actionName = "";
            switch (actionEnum)
            {
                case NET_FW_ACTION_.NET_FW_ACTION_ALLOW:
                    actionName = "Allow";
                    break;
                case NET_FW_ACTION_.NET_FW_ACTION_BLOCK:
                    actionName = "Block";
                    break;
                case NET_FW_ACTION_.NET_FW_ACTION_MAX:
                    actionName = "Max";
                    break;
                default:
                    actionName = "Unknown";
                    break;
            }
            return actionName;
        }

        /* Returns direction name */
        //Todo: What is Max?
        static public String getDirectionName(NET_FW_RULE_DIRECTION_ dirEnum)
        {
            String dirName = "";
            switch (dirEnum)
            {
                case NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN:
                    dirName = "In";
                    break;
                case NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT:
                    dirName = "Out";
                    break;
                case NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_MAX:
                    dirName = "Max";
                    break;
                default:
                    dirName = "Unknown";
                    break;
            }
            return dirName;
        }

        /* Assumes audit failures are enabled */
        /* List audit failure information     */
        //requires admin privileges
        //todo: report on lack of admin privs
        public void listAuditFailures(DateTime dt, bool shortApp = false)
        {
            string query = "*[System/EventID=5152 and System[TimeCreated[@SystemTime > '" + dt.ToString("yyyy-MM-ddTHH:mm:ss") + ".000000000Z']]]";
            //[System[TimeCreated[@SystemTime = '2011-12-20T00:42:53.000000000Z']]]
            EventLogQuery eventsQuery = new EventLogQuery("Security", PathType.LogName, query);

            try
            {
                EventLogReader logReader = new EventLogReader(eventsQuery);
                for (EventRecord eventdetail = logReader.ReadEvent(); eventdetail != null; eventdetail = logReader.ReadEvent())
                {
                    Console.WriteLine("{0} {1} {2} {3} {4} {5} {6} {7}", eventdetail.TimeCreated,
                                                                    (shortApp) ? Path.GetFileName(eventdetail.Properties[1].Value.ToString()) : eventdetail.Properties[1].Value,
                                                                    (eventdetail.Properties[2].Value.ToString() == "%%14593") ? "Out" : "In",
                                                                     eventdetail.Properties[3].Value,
                                                                     eventdetail.Properties[4].Value,
                                                                     eventdetail.Properties[5].Value,
                                                                     eventdetail.Properties[6].Value,
                                                                     Enum.GetName(typeof(ProtocolType), eventdetail.Properties[7].Value));
                    /*
                    for (int i = 0; i < eventdetail.Properties.Count; i++)
                    {
                        var value = eventdetail.Properties[i].Value;
                        Console.WriteLine("    Property[{0}] = {1} ({2})", i, value, value.GetType());
                    }
                     */
                    // Read Event details
                }
            }
            catch (EventLogNotFoundException e)
            {
                Console.WriteLine("Error while reading the event logs: {0}", e.Message);
                return;
            }
        }

        public static void OnEntryWritten(object source,
                                  EntryWrittenEventArgs entryArg)
        {
            var eventFields = new Dictionary<string,int>() {
                {"Application Name", 0},
                {"Direction", 1},
                {"Source Address", 2},
                {"Source Port", 3},
                {"Destination Address", 4},
                {"Destination Port", 5},
                {"Protocol", 6},
            };

            //the tail sometimes just dumps all
            //of the failed entry logs to the screen
            //i'm not sure if this is because of a rollover event or what
            //try to catch this by making sure that this log was generated in the 
            //last 30 seconds or less
            var dt = DateTime.Now;
            dt = dt.Add(new TimeSpan(0, 0, -30));
            if (entryArg.Entry.TimeWritten < dt)
            {
                return;
            }

            try
            {
                if (entryArg.Entry.InstanceId == 5152)
                {
                    //Console.WriteLine(entryArg.Entry.Message);
                    var props = new string[8];
                    var lines = entryArg.Entry.Message.Split('\n');
                    for (int i = 0; i < lines.Length; i++)
                    {
                        //Console.WriteLine(lines[i]);
                        var c = lines[i].IndexOf(':');
                        if (c > 0)
                        {
                            var k = lines[i].Substring(0, c).Trim();
                            if (eventFields.ContainsKey(k))
                            {
                                props[eventFields[k]] = lines[i].Substring(c+1).Trim();
                            }
                        }

                    }
                    
                    Console.WriteLine("{0} {1} {2} {3} {4} {5} {6} {7}", entryArg.Entry.TimeWritten,
                                                                     props[0],
                                                                    (props[1] == "%%14593") ? "Out" : "In",
                                                                     props[2],
                                                                     props[3],
                                                                     props[4],
                                                                     props[5],
                                                                     Enum.GetName(typeof(ProtocolType), Int32.Parse(props[6])));
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("error:" + e.Message);
            }
        }

        public void tailLog()
        {
            var log = new EventLog("Security");
            log.EntryWritten += new EntryWrittenEventHandler(OnEntryWritten);
            log.EnableRaisingEvents = true;
            Thread.Sleep(Timeout.Infinite);
        }
        /* too slow
        //https://stackoverflow.com/questions/5618667/to-read-a-particular-windows-security-log
        public void listAuditFailures()
        {

            // Specify your source name and log name (e.g. Application, System or some custom name)
            EventLog log = new EventLog("Security");

            // Enumerate through log entries
            foreach (EventLogEntry entry in log.Entries)
            {
                // Do something with log entries
                Console.WriteLine(entry.Message);
            }

            // You also may filter log entries by date (LINQ is used for this)
            //IEnumerable<EventLogEntry> blocked = log.Entries.Cast<EventLogEntry>().Where(x => (DateTime.Now - x.TimeGenerated).Seconds < 60);
            //Console.WriteLine("Count: {0}", blocked.Count<EventLogEntry>());

            foreach (EventLogEntry entry in log.Entries.Cast<EventLogEntry>().Where(x => (DateTime.Now - x.TimeGenerated).TotalSeconds < 60))
            {
                // Do something with log entries
                //Console.WriteLine(entry.Message);
                Console.WriteLine("{0} {1} {2}", DateTime.Now, (DateTime.Now - entry.TimeGenerated).Seconds, entry.TimeGenerated);

            }
        }
        */

        //requires admin privileges
        //todo: report on lack of admin privs
        public void enableWFPFailureAuditing()
        {
            Process p = new Process();
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.FileName = "cmd.exe";
            p.StartInfo.Arguments = "/C auditpol /set /SubCategory:\"Filtering Platform Packet Drop\" /failure:enable";
            p.Start();
            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();
            logger.Debug("enable log: {0}", output);
            Console.WriteLine(output);
        }

        //requires admin privileges
        //todo: report on lack of admin privs
        public void disableWFPFailureAuditing()
        {
            Process p = new Process();
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.FileName = "cmd.exe";
            p.StartInfo.Arguments = "/C auditpol /set /SubCategory:\"Filtering Platform Packet Drop\" /failure:disable";
            p.Start();
            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();
            logger.Debug("disable log: {0}", output);
            Console.WriteLine(output);
        }

        public Dictionary<bool,string> isWFPFailureAuditingEnabled()
        {
            var ret = new Dictionary<bool, string>();
            Process p = new Process();
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;
            p.StartInfo.FileName = "cmd.exe";
            p.StartInfo.Arguments = "/C auditpol /get /SubCategory:\"Filtering Platform Packet Drop\"";
            p.Start();
            string output = p.StandardOutput.ReadToEnd();
            string error = p.StandardError.ReadToEnd();
            p.WaitForExit();
            logger.Debug("log auditing stdout: {0}", output);
            logger.Debug("log auditing stderr: {0}", error);

            if(error.Contains("required privilege is not held"))
            {
                ret[false] = "Admin required";
            }
            else
            {
                ret[output.Contains("Failure")] = "";
            }
            
            return ret;
        }
    }
}