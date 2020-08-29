using System.Security.Cryptography;
using static System.Security.Cryptography.TripleDES;
using tdes = System.Security.Cryptography.TripleDES;

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
        static void InSecureObj()
        {
            var tripleDES = TripleDES.Create();
            var tripleDES1 = Create();
            var tripleDES2 = tdes.Create();
            var simpleDES = DES.Create();
            var rC2 = RC2.Create();
        }
        static void Secureobj()
        {
            var AES = Aes.Create();
        }
    }
}