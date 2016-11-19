using System;                                //default
using System.Collections.Generic;            //lists
using System.Runtime.InteropServices;        //SID lookup
using System.Security.Principal;             //SID lookup
using System.Text;                           //SID lookup
using System.Management;                     //SID lookup

namespace msuser
{
    enum SID_NAME_USE
    {
        SidTypeUser = 1,
        SidTypeGroup,
        SidTypeDomain,
        SidTypeAlias,
        SidTypeWellKnownGroup,
        SidTypeDeletedAccount,
        SidTypeInvalid,
        SidTypeUnknown,
        SidTypeComputer
    }

    class MSUsers
    {

        private const int ERROR_INSUFFICIENT_BUFFER = 122;
        private const int NO_ERROR = 0;

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool LookupAccountSid(
            string lpSystemName,
            [MarshalAs(UnmanagedType.LPArray)] byte[] Sid,
            System.Text.StringBuilder lpName,
            ref uint cchName,
            System.Text.StringBuilder ReferencedDomainName,
            ref uint cchReferencedDomainName,
            out SID_NAME_USE peUse); 

        public MSUsers()
        {

        }

        public Tuple<SID_NAME_USE, string> sidtoname(string inputsid)
        {
            StringBuilder name = new StringBuilder();
            uint cchName = (uint)name.Capacity;
            StringBuilder referencedDomainName = new StringBuilder();
            uint cchReferencedDomainName = (uint)referencedDomainName.Capacity;
            SID_NAME_USE sidUse;
            // Sid for BUILTIN\Administrators
            //byte[] Sid = new byte[] { 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2 };

            var sid = new SecurityIdentifier(inputsid);
            byte[] bytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(bytes, 0);

            int err = NO_ERROR;
            if (!LookupAccountSid(null, bytes, name, ref cchName, referencedDomainName, ref cchReferencedDomainName, out sidUse))
            {
                err = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                if (err == ERROR_INSUFFICIENT_BUFFER)
                {
                    name.EnsureCapacity((int)cchName);
                    referencedDomainName.EnsureCapacity((int)cchReferencedDomainName);
                    err = NO_ERROR;
                    if (!LookupAccountSid(null, bytes, name, ref cchName, referencedDomainName, ref cchReferencedDomainName, out sidUse))
                        err = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }
            if (err == 0)
            {
                return Tuple.Create((SID_NAME_USE)System.Enum.Parse(typeof(SID_NAME_USE), sidUse.ToString()), String.Format(@"{0}\{1}", referencedDomainName.ToString(), name.ToString()));
                //Console.WriteLine(@"Found account {0} : {1}\{2}", sidUse, referencedDomainName.ToString(), name.ToString());
            }
            else
            {
                return Tuple.Create(SID_NAME_USE.SidTypeInvalid, err.ToString());
                //Console.WriteLine(@"Error : {0}", err);
            }

        }

        public void checkUsers()
        {
            ManagementObjectSearcher query = new ManagementObjectSearcher("SELECT * FROM Win32_UserProfile");
            ManagementClass processClass = new ManagementClass("Win32_UserProfile");
            foreach (ManagementObject user in query.Get())
            {
                var userprops = new Dictionary<string, string>();
                bool print = false;
                foreach (PropertyData property in user.Properties)
                {
                    if (property.Value == null)
                    {
                        userprops.Add(property.Name.ToString(), "");
                    }
                    else
                    {
                        userprops.Add(property.Name.ToString(), property.Value.ToString());
                    }

                    if (property.Name == "SID")
                    {
                        Tuple<SID_NAME_USE, string> sid = this.sidtoname(property.Value.ToString());
                        if (sid.Item1 != SID_NAME_USE.SidTypeWellKnownGroup)
                        {
                            print = true;
                            userprops.Add(sid.Item1.ToString(), sid.Item2);
                        }
                    }
                }
                if (print)
                {
                    foreach (string key in userprops.Keys)
                    {
                        Console.WriteLine("{0}:{1}", key, userprops[key]);
                    }
                }

                // show the instance 
                Console.WriteLine();
            }
        }
    }
}