using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Web;

namespace Cryptography101.Algorithms
{
    public static class Vigenere
    {
        static Regex inputValidation = new Regex("[a-z]+", RegexOptions.Compiled, new TimeSpan(0, 0, 5));
        static Regex inputValidationSpacesAllowed = new Regex("[a-z ]+", RegexOptions.Compiled, new TimeSpan(0, 0, 5));

        static string plain = "abcdefghijklmnopqrstuvwxyz";
        static string[] square = new string[27];

        static Vigenere()
        {
            for (int i = 1; i <= 26; i++)
            {
                string rowContent = string.Empty;
                char currentCharacter = 'a';
                currentCharacter += (char)i;
                if (currentCharacter > 'z')
                {
                    currentCharacter = 'a';
                }

                for (int j = 0; j < 26; j++)
                {
                    rowContent += currentCharacter++;

                    if (currentCharacter > 'z')
                    {
                        currentCharacter = 'a';
                    }
                }
                square[i] = rowContent;
            }
        }

        public static string Encrypt(string plainText, string keyWord, bool allowSpace = false)
        {
            if (string.IsNullOrWhiteSpace(keyWord))
            {
                throw new ArgumentNullException("key");
            }

            Match keyIsValid = inputValidation.Match(keyWord);
            if (!keyIsValid.Success)
            {
                throw new ArgumentOutOfRangeException("key", "Must be a series of lowercase letters.");
            }

            if (allowSpace == false)
            {
                Match targetIsValid = inputValidation.Match(plainText);
                if (!targetIsValid.Success)
                {
                    throw new ArgumentOutOfRangeException("plainText", "Must be lower case English letters.");
                }
            }
            else
            {
                Match targetIsValid = inputValidationSpacesAllowed.Match(plainText);
                if (!targetIsValid.Success)
                {
                    throw new ArgumentOutOfRangeException("plainText", "Must be lower case English letters or spaces.");
                }
            }

            while (keyWord.Length < plainText.Length)
            {
                keyWord = keyWord + keyWord;
            }
            keyWord = keyWord.Substring(0, plainText.Length);

            string cipherText = string.Empty;

            for (int i = 0; i < plainText.Length; i++)
            {
                char cipherSelector = keyWord[i];
                string cipherRow = string.Empty;
                for (int rowIndex = 1; rowIndex <= 26; rowIndex++)
                {
                    if (square[rowIndex][0] == cipherSelector)
                    {
                        cipherRow = square[rowIndex];
                        break;
                    }
                }

                char characterToEncrypt = plainText[i];
                int cipherOffset = characterToEncrypt - 'a';
                char encryptedCharacter = cipherRow[cipherOffset];

                cipherText += encryptedCharacter;
            }

            return cipherText;
        }

        public static string Decrypt(string cipherText, string keyWord, bool allowSpace = false)
        {
            if (string.IsNullOrWhiteSpace(keyWord))
            {
                throw new ArgumentNullException("key");
            }

            Match keyIsValid = inputValidation.Match(keyWord);
            if (!keyIsValid.Success)
            {
                throw new ArgumentOutOfRangeException("key", "Must be a series of lowercase letters.");
            }

            if (allowSpace == false)
            {
                Match targetIsValid = inputValidation.Match(cipherText);
                if (!targetIsValid.Success)
                {
                    throw new ArgumentOutOfRangeException("target", "Must be lower case English letters.");
                }
            }
            else
            {
                Match targetIsValid = inputValidationSpacesAllowed.Match(cipherText);
                if (!targetIsValid.Success)
                {
                    throw new ArgumentOutOfRangeException("target", "Must be lower case English letters or spaces.");
                }
            }

            while (keyWord.Length < cipherText.Length)
            {
                keyWord = keyWord + keyWord;
            }
            keyWord = keyWord.Substring(0, cipherText.Length);

            string plainText = string.Empty;

            for (int i = 0; i < cipherText.Length; i++)
            {
                char cipherSelector = keyWord[i];
                string cipherRow = string.Empty;
                for (int rowIndex = 1; rowIndex <= 26; rowIndex++)
                {
                    if (square[rowIndex][0] == cipherSelector)
                    {
                        cipherRow = square[rowIndex];
                        break;
                    }
                }

                char characterToDecrypt = cipherText[i];
                int offset = cipherRow.IndexOf(characterToDecrypt);
                char decryptedCharacter = plain[offset];

                plainText += decryptedCharacter;
            }

            return plainText;
        }
    }
}