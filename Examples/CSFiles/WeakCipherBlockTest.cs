using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace CoreMVCWebApplication4
{
    public class WeakCipherMode
    {
        byte[] data = { 1, 2, 3 }, key = { 3, 4, 5 }, iv = { 5, 6, 7 };
        byte[] encryptedData = { 0 };
        int byteWritten = 0;

        public void Noncompliant()
        {
            RijndaelManaged rijndael = new RijndaelManaged() { };// Noncompliant
            AesManaged aes4 = new AesManaged
            {
                KeySize = 128,
                BlockSize = 128,
                Mode = CipherMode.ECB, // Noncompliant
                Padding = PaddingMode.PKCS7
            };
            RSACryptoServiceProvider RSA1 = new RSACryptoServiceProvider();
            encryptedData = RSA1.Encrypt(data, false); // Noncompliant
            RSA1.TryEncrypt(data, encryptedData, RSAEncryptionPadding.Pkcs1, out byteWritten); // Noncompliant
            encryptedData = RSA1.Encrypt(data, RSAEncryptionPadding.Pkcs1); // Noncompliant
        }
        public void Compliant()
        {
            GcmBlockCipher blockCipher = new GcmBlockCipher(new AesEngine()); // Compliant

            var aesGcm = new AesGcm(key); // Compliant

            RSACryptoServiceProvider RSA1 = new RSACryptoServiceProvider();
            encryptedData = RSA1.Encrypt(data, true); // Compliant
            RSA1.TryEncrypt(data, encryptedData, RSAEncryptionPadding.OaepSHA512, out byteWritten); // Compliant
            encryptedData = RSA1.Encrypt(data, RSAEncryptionPadding.OaepSHA1); // Compliant
        }
    }
}