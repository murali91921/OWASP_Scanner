using System;
using System.DirectoryServices;
using System.Text.RegularExpressions;
using Microsoft.Security.Application;
using Microsoft.Security;

using mscorlib;

namespace WebApplication1.Models
{
    public class LDAPExample1
    {
        public void Search(string username, string password)
        {
			//string search = "(&(uid=";
			/* Testing */
			search = "(&(uid=" + username + ")(userPassword=" + password + "))";
            DirectorySearcher directorySearch1 = new DirectorySearcher { Filter = search };
            directorySearch1.FindOne();

            DirectorySearcher directorySearch2 = new DirectorySearcher("(&(uid=" + username + ")(userPassword=" + password + "))");
            directorySearch2.FindOne();

            DirectorySearcher directorySearch3 = new DirectorySearcher("(&(uid=" + Encoder.LdapFilterEncode(username) +
                ")(userPassword=" + Encoder.LdapFilterEncode(password) + "))");
            directorySearch3.FindOne();

            username = Encoder.LdapFilterEncode(username);
            password = Encoder.LdapFilterEncode(password);
            string search4 = "(&(uid=" + username + ")(userPassword=" + password + "))";
            DirectorySearcher directorySearch4 = new DirectorySearcher(search4);
            directorySearch4.Filter = "(&(uid=" + Encoder.LdapFilterEncode(username) + ")(userPassword=" + Encoder.LdapFilterEncode(password) + "))";
            directorySearch4.FindAll();
        }

        public void SearchCheck(string username, string password)
        {
            if (!Regex.IsMatch(username, "^[a-zA-Z]+$") || !Regex.IsMatch(password, "^[a-zA-Z0-9]+$"))
            {
                return;
            }
            string search3 = "(&(uid=" + username + ")(userPassword=" + password + "))";
            DirectorySearcher directorySearch3 = new DirectorySearcher(search3);
            directorySearch3.FindOne();
        }
    }
}