using System;
using System.IO;

namespace Sample2
{
    class Class1
    {
        // Password is AKIAHI323HKH1IWUQEES //Sensitive
        /* key : AKIAHI234HKH1IWUQEEN  */
        /* Password is
        AKIAHI456HKH1IWUQEEN */
        /**** Password is
        *  AKIAHI789HKH1IWUQEEN
        ****/

        public string classPassword = "classValue"; //Sensitive
        public string classPassword1; //non-Sensitive
        static void Main(string[] args)
        {
            string methodPass="methodPassValue"; //Sensitive
            string methodPassword1;//non-Sensitive
            Console.WriteLine("Hello World!");
            for(int i=0;i<=10;i++)
            {
                string blockPasswd = "blockPassValue"; //Sensitive
                string blockpwd = ""; //Sensitive
                string appsecret = ""; //Sensitive
                string appkey = ""; //Sensitive
                string appsecret = ""; //Sensitive
                string api_token = ""; //Sensitive
                string gitlab_secret = ""; //Sensitive
                string github_key = ""; //Sensitive
                string slack_secret = ""; //Sensitive
                string google_api_token = ""; //Sensitive
                string client_secret = ""; //Sensitive
                string client_token = ""; //Sensitive
                String client_key = ""; //Sensitive
                string client_key_generate; //Non-Sensitive
                string client_key_duplicate=client_key; //Non-Sensitive
                int minpasswdlength=10; //Non-Sensitive
                string client_key_concat="AKIA"+client_key;//Non-Sensitive
                Console.WriteLine(i);
            }
        }
    }
}