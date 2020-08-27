using System.Security.Cryptography;

namespace VulnerableApp
{
    public class WeakSymmetric1
    {
		static void InSecure()
        {
            var tripleDES1 = new TripleDESCryptoServiceProvider();
            var simpleDES = new DESCryptoServiceProvider();
            var RC2 = new RC2CryptoServiceProvider();
            RC2 = new RC2CryptoServiceProvider { Mode = CipherMode.ECB };
            RC2 = new RC2CryptoServiceProvider { Mode = CipherMode.CBC };
            RC2.Mode = CipherMode.CFB;
        }
        static void Secure()
        {
            var AES = new AesCryptoServiceProvider();
        }
    }
}