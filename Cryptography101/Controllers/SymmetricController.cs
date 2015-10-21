using System;
using System.Security.Cryptography;
using System.Text;
using System.Web.Mvc;
using System.IO;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace Cryptography101.Controllers
{
    public class SymmetricController : Controller
    {
        public ActionResult Index()
        {
            return View(new SymmetricModel());
        }

        [HttpPost]
        public ActionResult Index(SymmetricModel model)
        {
            if (model.Action == "encrypt")
            {
                var plainTextAsBytes = Encoding.Unicode.GetBytes(model.PlainText);              
                var cryptoProvider = new AesCryptoServiceProvider();
                byte[] masterKey;

                if (!string.IsNullOrWhiteSpace(model.Key))
                {
                    if (!string.IsNullOrWhiteSpace(model.IV))
                    {
                        cryptoProvider.Key = Convert.FromBase64String(model.Key);
                        cryptoProvider.IV = Convert.FromBase64String(model.IV);
                    }
                    else
                    {
                        throw new Exception("If you provide a key or IV you must provide both.");
                    }
                }
                else if (!string.IsNullOrEmpty(model.IV))
                {
                    throw new Exception("If you provide a key or IV you must provide both.");
                }

                masterKey = cryptoProvider.Key;
                var encryptionKey = DeriveKey("encryption", masterKey, cryptoProvider.KeySize / 8);
                var signingKey = DeriveKey("signature", masterKey, 64);

                ICryptoTransform cryptoTransform =
                    cryptoProvider.CreateEncryptor(encryptionKey, cryptoProvider.IV);

                var outputStream = new MemoryStream();
                var cryptoStream = new CryptoStream(
                    outputStream,
                    cryptoTransform,
                    CryptoStreamMode.Write);

                cryptoStream.Write(plainTextAsBytes, 0, plainTextAsBytes.Length);
                cryptoStream.FlushFinalBlock();

                byte[] cipherTextAsBytes = outputStream.ToArray();

                var signingAlgorithm = new HMACSHA256(signingKey);
                var signature = signingAlgorithm.ComputeHash(cipherTextAsBytes);       

                model.PlainText = string.Empty;
                model.CipherText = Convert.ToBase64String(cipherTextAsBytes);
                model.Key = Convert.ToBase64String(masterKey);
                model.IV = Convert.ToBase64String(cryptoProvider.IV);
                model.Signature = Convert.ToBase64String(signature);

            }
            else if (model.Action == "decrypt")
            {
                var cipherTextAsBytes = Convert.FromBase64String(model.CipherText);
                var cryptoProvider = new AesCryptoServiceProvider();
                byte[] masterKey;

                cryptoProvider.Key = Convert.FromBase64String(model.Key);
                cryptoProvider.IV = Convert.FromBase64String(model.IV);

                masterKey = cryptoProvider.Key;
                var encryptionKey = DeriveKey("encryption", masterKey, cryptoProvider.KeySize / 8);
                var signingKey = DeriveKey("signature", masterKey, 64);

                var signingAlgorithm = new HMACSHA256(signingKey);
                var signature = signingAlgorithm.ComputeHash(cipherTextAsBytes);

                if (!HashCompare(signature, Convert.FromBase64String(model.Signature)))
                {
                    throw new Exception("Invalid Signature.");
                }

                ICryptoTransform cryptoTransform =
                    cryptoProvider.CreateDecryptor(encryptionKey, cryptoProvider.IV);

                var outputStream = new MemoryStream();
                var cryptoStream = new CryptoStream(
                    outputStream,
                    cryptoTransform,
                    CryptoStreamMode.Write);

                cryptoStream.Write(cipherTextAsBytes, 0, cipherTextAsBytes.Length);
                cryptoStream.FlushFinalBlock();

                byte[] plainTextAsBytes = outputStream.ToArray();
                model.PlainText = Encoding.Unicode.GetString(plainTextAsBytes);
                model.CipherText = string.Empty;
            }

            ModelState.Clear();

            return View(model);
        }

        private byte[] DeriveKey(string purpose, byte[] masterKey, int keySize)
        {
            var kdf = new Rfc2898DeriveBytes
                (masterKey,
                Encoding.Unicode.GetBytes(purpose),
                1000);

            return kdf.GetBytes(keySize);
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static bool HashCompare(byte[] array1, byte[] array2)
        {
            const byte Zero = 0;
            int maxLength = array1.Length > array2.Length ? array1.Length : array2.Length;
            bool wereEqual = array1.Length == array2.Length;
            byte[] paddedArray1 = new byte[maxLength];
            byte[] paddedArray2 = new byte[maxLength];
            for (int i = 0; i < maxLength; i++)
            {
                paddedArray1[i] = array1.Length > i ? array1[i] : Zero;
                paddedArray2[i] = array2.Length > i ? array2[i] : Zero;
            }
            bool compareResult = true;
            for (int i = 0; i < maxLength; i++)
            {
                compareResult = compareResult & paddedArray1[i] == paddedArray2[i];
            }
            return compareResult & wereEqual;
        }

    }

    public class SymmetricModel
    {
        public string Action { get; set; }

        [DisplayName("Plain Text")]
        public string PlainText { get; set; }

        [DisplayName("Cipher Text")]
        public string CipherText { get; set; }
        
        public string Signature { get; set; }

        public string Key { get; set; }
        public string IV { get; set; }
    }
}