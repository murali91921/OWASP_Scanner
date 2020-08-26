using System;
//using Cryptography = System.Security.Cryptography;
using System.Security.Cryptography;

//below namespaces are not used, These are only for loading the dll.
using System.Security.Cryptography.Algorithms;
using System.Security.Cryptography.Primitives;
using System.Runtime;

namespace ConsoleCoreHashApp1
{
    class Program
    {
        static void Main(string[] args)
        {

        }

        static String generateWeakHashingMD5()
        {
            string source = "Hello World!";
            MD5 md5 = MD5.Create();
            byte[] data = md5.ComputeHash(Encoding.UTF8.GetBytes(source));

            StringBuilder sBuilder = new StringBuilder();
            for (int i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }

            // Return the hexadecimal string
            return sBuilder.ToString();
        }
    }
    class ExampleClass
    {
        public void ExampleMethod(byte[] password, byte[] salt, int iterations, HashAlgorithmName hashAlgorithm)
        {
            var Md5rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, salt, iterations,HashAlgorithmName.MD5);
            var SHA1rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA1);
            var SHA256rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, salt, iterations,HashAlgorithmName.SHA256);
        }
    }
}
