using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace Cryptography101.Controllers
{
    public class VigenereCipherController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Index(string command, string plainText, string cipherText, string keyword)
        {
            if (command == "encrypt" && !string.IsNullOrEmpty(plainText))
            {
                ViewBag.CipherText = Algorithms.Vigenere.Encrypt(plainText, keyword, true);
            }

            if (command == "decrypt" && !string.IsNullOrEmpty(cipherText))
            {
                ViewBag.PlainText = Algorithms.Vigenere.Decrypt(cipherText, keyword, true);
            }

            ViewBag.KeyWord = keyword;

            return View();
        }
    }
}