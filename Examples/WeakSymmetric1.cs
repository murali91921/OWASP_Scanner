using System.Security.Cryptography;

namespace VulnerableApp
{
    public class WeakSymmetric1
    {
		static void InSecure()
        {
            var tripleDES1 = new TripleDESCryptoServiceProvider();
            var simpleDES = new DESCryptoServiceProvider();
            RC2CryptoServiceProvider RC2 = new RC2CryptoServiceProvider();
        }
        static void Secure()
        {
            var AES = new AesCryptoServiceProvider();
        }
    }
}