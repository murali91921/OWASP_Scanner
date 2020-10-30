using System;
using System.DirectoryServices;

namespace LdapSecure
{
    public class LdapSecureTest
    {
        public void UnsafeMethod(string adPath)
        {
			DirectoryEntry myDirectoryEntry = new DirectoryEntry(adPath);
			myDirectoryEntry = new DirectoryEntry();
			myDirectoryEntry = new DirectoryEntry(adPath)
			{
				AuthenticationType = AuthenticationTypes.None // Noncompliant
			};
			myDirectoryEntry.AuthenticationType = AuthenticationTypes.None; // Noncompliant
			DirectoryEntry myDirectoryEntry = new DirectoryEntry(adPath, "u", "p", AuthenticationTypes.None); // Noncompliant
        }
        public void SafeMethod(string myADSPath)
        {
			//We're considering the application as .Net 3.5 or above
			DirectoryEntry myDirectoryEntry = new DirectoryEntry(myADSPath); // Compliant; default DirectoryEntry.AuthenticationType property value is "Secure" from .NET Framework 2.0
			DirectoryEntry myDirectoryEntry = new DirectoryEntry(myADSPath, "u", "p", AuthenticationTypes.Secure);
        }
    }
}