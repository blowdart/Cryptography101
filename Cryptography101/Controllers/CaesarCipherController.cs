using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Web.Mvc;

namespace Cryptography101.Controllers
{
    public class CaesarCipherController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Index(string command, string plainText, string cipherText, int key)
        {
            if (key < 1 || key > 25)
            {
                throw new ArgumentOutOfRangeException("key", key.ToString(CultureInfo.InvariantCulture));
            }

            ViewBag.Key = key;

            if (command == "encrypt" && !string.IsNullOrEmpty(plainText))
            {
                ViewBag.CipherText = Algorithms.Caesar.Encrypt(plainText, key);          
            }

            if (command == "decrypt" && !string.IsNullOrEmpty(cipherText))
            {
                ViewBag.PlainText = Algorithms.Caesar.Decrypt(cipherText, key);
            }

            return View();
        }

        public ActionResult BruteForce()
        {
            return View();
        }

        [HttpPost]
        public ActionResult BruteForce(string plainText, int key)
        {
            var cipherText = Algorithms.Caesar.Encrypt(plainText, key);

            ViewBag.PlainText = plainText;
            ViewBag.Key = key;
            ViewBag.CipherText = cipherText;

            var attempts = new Dictionary<int, string>();
            for (int i = 1; i < 26; i++)
            {
                attempts.Add(i, Algorithms.Caesar.Decrypt(cipherText, i));
            }

            return View(attempts);
        }

        public ActionResult FrequencyAnalysis()
        {
            string plainText = "You can dance you can jive having the time of your life See that girl watch that scene digging the Dancing Queen".ToLower();
            var random = new Random();
            int key = random.Next(1, 25);

            System.Diagnostics.Debug.WriteLine("key: " + key);

            string cipherText = Algorithms.Caesar.Encrypt(plainText, key, true);

            ViewBag.CipherText = cipherText;

            ViewBag.PlainText = null;

            return View();
        }

        [HttpPost]
        public ActionResult FrequencyAnalysis(string cipherText)
        {
            const string englishLettersByFrequency = "etaoinshrdlcumwfgypbvkjxqz";

            var cipherTextLetterFrequency = new Dictionary<char, int>();

            for (char c = 'a'; c <= 'z'; c++)
            {
                cipherTextLetterFrequency.Add(c, 0);
            }

            foreach (char c in cipherText)
            {
                if (!cipherTextLetterFrequency.Keys.Contains(c))
                {
                    continue;
                }

                cipherTextLetterFrequency[c] = cipherTextLetterFrequency[c] + 1;
            }

            var cipherLettersSortedByFrequency = (from keyValuePair in cipherTextLetterFrequency
                                                  orderby keyValuePair.Value descending
                                                  select keyValuePair.Key).ToArray();

            var mostFrequentLetterInCipherText = cipherLettersSortedByFrequency[0];

            int key = (englishLettersByFrequency[0] - mostFrequentLetterInCipherText) * -1;

            var guessedPlainText = Algorithms.Caesar.Decrypt(cipherText, key, true);

            ViewBag.Key = key;
            ViewBag.PlainText = guessedPlainText;

            return View();
        }
    }
}