using System;
using System.Security.Cryptography;

using mscorlib;

namespace WebApplication1.Models
{
    public class InsecureRandomExample1
    {
        int i = new Random().Next();
        double d = new Random().NextDouble();
        Random random = new Random();
        public void Search()
        {
            Random random = new Random(1000);
            Console.WriteLine(random.Next());
            random = new Random(2000);
            Console.WriteLine(random.NextDouble());

            RNGCryptoServiceProvider provider = new RNGCryptoServiceProvider();
            var byteArray = new byte[4];
            provider.GetBytes(byteArray);

            RandomNumberGenerator randomNumber = RandomNumberGenerator.Create();
            randomNumber.GetBytes(byteArray);
            random.NextBytes(byteArray);
        }
    }
}