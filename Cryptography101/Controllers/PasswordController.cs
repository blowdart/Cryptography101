using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Web;
using System.Web.Mvc;

using Microsoft.AspNet.Cryptography.KeyDerivation;
using System.Runtime.CompilerServices;

namespace Cryptography101.Controllers
{
    public class PasswordController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Index(string password, string hash, string salt, string command)
        {
            if (command == "hash")
            {
                var newSalt = GenerateRandomBytes(256 / 8);
                ViewBag.Salt = Convert.ToBase64String(newSalt);
                ViewBag.Hash = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                    password,
                    newSalt,
                    KeyDerivationPrf.HMACSHA256,
                    10000,
                    256 / 8));
            }
            else if (command == "validate")
            {
                var providedSalt = Convert.FromBase64String(salt);

                var calculatedHash = KeyDerivation.Pbkdf2(
                    password,
                    providedSalt,
                    KeyDerivationPrf.HMACSHA256,
                    10000,
                    256 / 8);


                if (HashCompare(calculatedHash, Convert.FromBase64String(hash)))
                {
                    ViewBag.Result = "Hashes match";
                }
                else
                {
                    ViewBag.Result = "NO MATCH";
                }

                ViewBag.Salt = salt;
                ViewBag.Hash = hash;

            }

            ViewBag.Password = password;
 
            return View();
        }

        public static byte[] GenerateRandomBytes(int length)
        {
            byte[] randomArray = new byte[length];
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            rng.GetBytes(randomArray);
            return randomArray;
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
}