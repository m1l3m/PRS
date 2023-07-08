using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;

namespace DiffieHellmanED
{
    public class DiffieHellman : IDisposable
    {
        //polja za referenciranje AES klase, ECDiffieHellman klase i public key
        #region Private Fields
        private Aes aes = null;
        private ECDiffieHellman diffieHellman = null;

        private readonly byte[] publicKey;
        #endregion

        //konstruktor klase
        #region Constructor
        public DiffieHellman()
        {
            this.aes = new AesCryptoServiceProvider();

            this.diffieHellman = ECDiffieHellman.Create();

            // Public key koji se salje drugoj strani
            this.publicKey = this.diffieHellman.PublicKey.ToByteArray();
        }
        #endregion


        // geteri za Public Key i IV (Initialization Vector)
        #region Public Properties
        public byte[] PublicKey
        {
            get
            {
                return this.publicKey;
            }
        }

        public byte[] IV
        {
            get
            {
                return this.aes.IV;
            }
        }
        #endregion


        //Metode
        #region Public Methods

        //Metoda za enkripciju
        //Koristi public key druge strane i enkriptuje poruku
        //Na osnovu public key druge strane se generise derivedKey
        //kojim se enkriptuje poruka
        public byte[] Encrypt(byte[] publicKey, string secretMessage)
        {
            byte[] encryptedMessage;
            using (ECDiffieHellman otherParty = ECDiffieHellman.Create())
            {
                var otherKey = ECDiffieHellmanCngPublicKey.FromByteArray(publicKey, CngKeyBlobFormat.EccPublicBlob);
                byte[] derivedKey = diffieHellman.DeriveKeyMaterial(otherKey);
                aes.Key = derivedKey;

                using (MemoryStream cipherText = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(cipherText, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        byte[] ciphertextMessage = Encoding.UTF8.GetBytes(secretMessage);
                        cryptoStream.Write(ciphertextMessage, 0, ciphertextMessage.Length);
                    }
                    encryptedMessage = cipherText.ToArray();
                }
            }

            return encryptedMessage;
        }

        public string Decrypt(byte[] publicKey, byte[] encryptedMessage, byte[] iv)
        {
            string decryptedMessage;
            using (ECDiffieHellman otherParty = ECDiffieHellman.Create())
            {
                var otherKey = ECDiffieHellmanCngPublicKey.FromByteArray(publicKey, CngKeyBlobFormat.EccPublicBlob);
                byte[] derivedKey = diffieHellman.DeriveKeyMaterial(otherKey);
                aes.Key = derivedKey;
                aes.IV = iv;
                aes.Padding = PaddingMode.Zeros;

                using (MemoryStream plainText = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(plainText, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(encryptedMessage, 0, encryptedMessage.Length);
                    }
                    decryptedMessage = Encoding.UTF8.GetString(plainText.ToArray());
                }
            }

            return decryptedMessage;
        }

        #endregion



        //cisti resurse
        #region IDisposable Members
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }


        //cisti resurse
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (this.aes != null)
                    this.aes.Dispose();

                if (this.diffieHellman != null)
                    this.diffieHellman.Dispose();
            }
        }
        #endregion
    }
}