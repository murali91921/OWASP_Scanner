using System;
using System.IO;

namespace Sample2
{
    class Credentials3
    {
        static string ApiKey="ABCDE"+"FG";//Non-Sensitive
        static void Main(string[] args)
        {
            ApiKey = "key value"+"ABCDE";//Non-Sensitive
            String apiKey = "";          //Non-Sensitive, value is empty
            apiKey = "testing123";       //Sensitive
            string key;                  //Non-Sensitive, no value

            key = "testing4321";         //Sensitive
            key = "";                    //Non-Sensitive, value is empty
            string password = "";        //Non-Sensitive, value is empty
            if(password == "123445")     //Sensitive, value is checking
            {
                Console.WriteLine("Password not changed");
            }
            Console.WriteLine(i);
            }
        }
    }
}