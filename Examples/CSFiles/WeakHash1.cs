using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

//below namespaces are not used, These are only for loading the dll.
using mscorlib;

namespace SecurityGuardSamples
{
    class WeakHashing
    {
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

        static String generateWeakHashingSHA1()
        {
            string source = "Hello World!";
            SHA1 sha1 = SHA1.Create();
            byte[] data = sha1.ComputeHash(Encoding.UTF8.GetBytes(source));

            StringBuilder sBuilder = new StringBuilder();
            for (int i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }

            // Return the hexadecimal string
            return sBuilder.ToString();
        }

        static String generateSecureHashing()
        {
            string source = "Hello World!";
            SHA256 sha256 = SHA256.Create();
            byte[] data = sha256.ComputeHash(Encoding.UTF8.GetBytes(source));

            StringBuilder sBuilder = new StringBuilder();
            for (int i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }

            // Return the hexadecimal string
            return sBuilder.ToString();
        }
    }
    public class InsecureHashAlgorithm
    {
        public void Hash(byte[] temp)
        {
            using (var sha1 = new SHA1Managed()) //Noncompliant {{Use a stronger hashing/asymmetric algorithm.}}
                                                 //                                ^^^^^^^^^^^
            {
            }
            using (var sha1 = new SHA1CryptoServiceProvider()) //Noncompliant
            {
            }
            using (var sha256 = new SHA256Managed())
            {
            }
            using (var sha256 = (HashAlgorithm)CryptoConfig.CreateFromName("SHA256Managed"))
            {
            }
            using (var sha256 = HashAlgorithm.Create("SHA256Managed"))
            {
            }
        }

        public void Md5Calls()
        {
            byte[] temp = null;

            using (var md5 = new MD5CryptoServiceProvider()) //Noncompliant
            {
                var hash = md5.ComputeHash(temp);
            }

            using (var md5 = (HashAlgorithm)CryptoConfig.CreateFromName("MD5")) //Noncompliant
                                                                                //                                          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
            {
                var hash = md5.ComputeHash(temp);
            }
            using (var md5 = HashAlgorithm.Create("MD5")) //Noncompliant
            {
                var hash = md5.ComputeHash(temp);
            }
            var algoName = "MD5";
            using (var md5 = (HashAlgorithm)CryptoConfig.CreateFromName(algoName)) // not able to recognize
            {
                var hash = md5.ComputeHash(temp);
            }
        }

        public void DsaCalls()
        {
            using (var dsa = new DSACryptoServiceProvider()) // Noncompliant
            {
            }
            using (var dsa = DSA.Create()) // Noncompliant
            {
            }
            using (var dsa = (AsymmetricAlgorithm)CryptoConfig.CreateFromName("DSA")) // Noncompliant
            {
            }
            using (var dsa = AsymmetricAlgorithm.Create("DSA")) // Noncompliant
            {
            }
        }

        public void HmaCalls()
        {
            using (var hmac = new HMACSHA1()) // Noncompliant
            {
            }
            using (var hmac = HMAC.Create()) // Noncompliant
            {
            }
            using (var hmacmd5 = HMACMD5.Create("HMACMD5")) // Noncompliant
            {
            }
            using (var hmacmd5 = KeyedHashAlgorithm.Create("HMACMD5")) // Noncompliant
            {
            }
            using (var hmacmd5 = (KeyedHashAlgorithm)CryptoConfig.CreateFromName("HMACMD5")) // Noncompliant
            {
            }

            using (var hmacripemd160 = HMACRIPEMD160.Create("HMACRIPEMD160")) // Noncompliant
            {
            }
            using (var hmacripemd160 = KeyedHashAlgorithm.Create("HMACRIPEMD160")) // Noncompliant
            {
            }
            using (var hmacripemd160 = (KeyedHashAlgorithm)CryptoConfig.CreateFromName("HMACRIPEMD160")) // Noncompliant
            {
            }

            using (var hmacsha256 = HMACSHA256.Create("HMACSHA256"))
            {
            }
            using (var hmacsha256 = KeyedHashAlgorithm.Create("HMACSHA256"))
            {
            }
            using (var hmacsha256 = (KeyedHashAlgorithm)CryptoConfig.CreateFromName("HMACSHA256"))
            {
            }
        }

        public void RipemdCalls()
        {
            using (var ripemd160 = RIPEMD160.Create()) // Noncompliant
            {
            }
            using (var ripemd160 = HashAlgorithm.Create("RIPEMD160")) // Noncompliant
            {
            }
            using (var ripemd160 = (HashAlgorithm)CryptoConfig.CreateFromName("RIPEMD160")) // Noncompliant
            {
            }

            using (var ripemd160Managed = RIPEMD160Managed.Create()) // Noncompliant
            {
            }
            using (var ripemd160Managed = HashAlgorithm.Create("RIPEMD160Managed")) // Noncompliant
            {
            }
            using (var ripemd160Managed = (HashAlgorithm)CryptoConfig.CreateFromName("RIPEMD160Managed")) // Noncompliant
            {
            }
        }
    }
}