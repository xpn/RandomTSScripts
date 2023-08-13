using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Policy;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using static LAPSDecrypt.Win32;
using static System.Net.Mime.MediaTypeNames;

namespace LAPSDecrypt
{
    internal class Win32
    {
        [Flags]
        public enum ProtectFlags
        {
            NCRYPT_SILENT_FLAG = 0x00000040,
        }

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate int PFNCryptStreamOutputCallback(IntPtr pvCallbackCtxt, IntPtr pbData, int cbData, [MarshalAs(UnmanagedType.Bool)] bool fFinal);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct NCRYPT_PROTECT_STREAM_INFO
        {
            public PFNCryptStreamOutputCallback pfnStreamOutput;
            public IntPtr pvCallbackCtxt;
        }

        [Flags]
        public enum UnprotectSecretFlags
        {
            NCRYPT_UNPROTECT_NO_DECRYPT = 0x00000001,
            NCRYPT_SILENT_FLAG = 0x00000040,
        }

        [DllImport("ncrypt.dll")]
        public static extern uint NCryptStreamOpenToUnprotect(in NCRYPT_PROTECT_STREAM_INFO pStreamInfo, ProtectFlags dwFlags, IntPtr hWnd, out IntPtr phStream);

        [DllImport("ncrypt.dll")]
        public static extern uint NCryptStreamUpdate(IntPtr hStream, IntPtr pbData, int cbData, [MarshalAs(UnmanagedType.Bool)] bool fFinal);

        [DllImport("ncrypt.dll")]
        public static extern uint NCryptUnprotectSecret(out IntPtr phDescriptor, Int32 dwFlags, IntPtr pbProtectedBlob, uint cbProtectedBlob, IntPtr pMemPara, IntPtr hWnd, out IntPtr ppbData, out uint pcbData);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        public static extern uint NCryptGetProtectionDescriptorInfo(IntPtr hDescriptor, IntPtr pMemPara, int dwInfoType, out string ppvInfo);

    }
    internal class Program
    {
        static int delegateCallback(IntPtr pvCallbackCtxt, IntPtr pbData, int cbData, [MarshalAs(UnmanagedType.Bool)] bool fFinal)
        {
            byte[] data = new byte[cbData];
            Marshal.Copy(pbData, data, 0, cbData);
            string str = Encoding.Unicode.GetString(data);

            Console.WriteLine("[*] Password is: {0}", str);

            return 0;
        }

        static void Main(string[] args)
        {
            string[] attributeList = new string[]
            {
                "msLAPS-PasswordExpirationTime",
                "msLAPS-Password",
                "msLAPS-EncryptedPassword",
                "msLAPS-EncryptedPasswordHistory",
                "msLAPS-EncryptedDSRMPassword",
                "msLAPS-EncryptedDSRMPasswordHistory",
                "ms-Mcs-AdmPwd",
                "ms-Mcs-AdmPwdExpirationTime"
            };

            // Parse arguments for DN and DC
            Console.WriteLine("LAPSDecrypt POC by @_xpn_");

            if (args.Length != 2)
            {
                Console.WriteLine("Usage: LAPSDecrypt.exe <DN> <DC>");
                Console.WriteLine("Example: LAPSDecrypt.exe \"CN=CA01,OU=LAPSManaged,DC=lab,DC=local\" \"dc01.lab.local\"");
                return;
            }

            string dn = args[0];
            string dc = args[1];

            string filter = string.Format("(&(objectClass={0})({1}={2}))", "computer", "distinguishedName", dn);

            // Create a new ldap connection
            LdapConnection ldapConnection = new LdapConnection(dc);
            ldapConnection.SessionOptions.ProtocolVersion = 3;
            ldapConnection.Bind();

            SearchRequest searchRequest = new SearchRequest(dn, filter, SearchScope.Base, attributeList);
            SearchResponse searchResponse = ldapConnection.SendRequest(searchRequest) as SearchResponse;
            SearchResultEntry searchResultEntry = searchResponse.Entries[0];
            if (searchResponse.Entries.Count != 1)
            {
                Console.WriteLine("[!] Could not find computer object");
                return;
            }

            foreach (string attVal in searchResultEntry.Attributes.AttributeNames)
            {
                if (StringComparer.InvariantCultureIgnoreCase.Equals(attVal, "msLAPS-PasswordExpirationTime"))
                {
                    var expiry = (searchResultEntry.Attributes["msLAPS-PasswordExpirationTime"].GetValues(typeof(string))[0] as string);
                    Console.WriteLine("[*] Expiry time is: {0}", expiry);
                }
                else if (StringComparer.InvariantCultureIgnoreCase.Equals(attVal, "msLAPS-Password"))
                {
                    var unencryptedPass = (searchResultEntry.Attributes["msLAPS-Password"].GetValues(typeof(string))[0] as string);
                    Console.WriteLine("[*] Unencrypted Password: {0}", unencryptedPass);

                }
                else if (StringComparer.InvariantCultureIgnoreCase.Equals(attVal, "msLAPS-EncryptedPassword"))
                {
                    byte[] encryptedPass = (searchResultEntry.Attributes["msLAPS-EncryptedPassword"].GetValues(typeof(byte[]))[0] as byte[]);
                    Console.WriteLine("[*] Found encrypted password of length: {0}", encryptedPass.Length);

                    Win32.NCRYPT_PROTECT_STREAM_INFO info = new NCRYPT_PROTECT_STREAM_INFO
                    {
                        pfnStreamOutput = new PFNCryptStreamOutputCallback(delegateCallback),
                        pvCallbackCtxt = IntPtr.Zero
                    };

                    IntPtr handle;
                    IntPtr handle2;
                    IntPtr secData;
                    uint secDataLen;
                    NTAccount ntaccount;

                    uint ret = Win32.NCryptStreamOpenToUnprotect(info, ProtectFlags.NCRYPT_SILENT_FLAG, IntPtr.Zero, out handle);
                    if (ret == 0)
                    {
                        IntPtr alloc = Marshal.AllocHGlobal(encryptedPass.Length);
                        Marshal.Copy(encryptedPass, 16, alloc, encryptedPass.Length - 16);

                        // Get the authorized decryptor of the blob
                        ret = Win32.NCryptUnprotectSecret(out handle2, 0x41, alloc, (uint)encryptedPass.Length - 16, IntPtr.Zero, IntPtr.Zero, out secData, out secDataLen);
                        if (ret == 0)
                        {
                            string sid;

                            ret = NCryptGetProtectionDescriptorInfo(handle2, IntPtr.Zero, 1, out sid);
                            if (ret == 0)
                            {
                                SecurityIdentifier securityIdentifier = new SecurityIdentifier(sid.Substring(4, sid.Length - 4));

                                try
                                {
                                    ntaccount = (securityIdentifier.Translate(typeof(NTAccount)) as NTAccount);

                                    Console.WriteLine("[*] Authorized Decryptor: {0}", ntaccount.ToString());
                                }
                                catch
                                {
                                    Console.WriteLine("[*] Authorized Decryptor SID: {0}", securityIdentifier.ToString());
                                }
                            }
                        }

                        // Decrypt the blob
                        ret = Win32.NCryptStreamUpdate(handle, alloc, encryptedPass.Length - 16, true);
                        Console.WriteLine("[*] Decrypted Password");
                    }

                }
            }
        }
    }
}