using System;
using System.Text.RegularExpressions;

namespace Cryptography101.Algorithms
{
    public static class Caesar
    {
        static Regex inputValidation = new Regex("[a-z]+", RegexOptions.Compiled, new TimeSpan(0, 0, 5));
        static Regex inputValidationSpacesAllowed = new Regex("[a-z ]+", RegexOptions.Compiled, new TimeSpan(0, 0, 5));

        public static string Encrypt(string plainText, int key, bool allowSpace = false)
        {
            return Transform(plainText, key, allowSpace);
        }

        public static string Decrypt(string cipherText, int key, bool allowSpace = false)
        {
            return Transform(cipherText, -key, allowSpace);
        }

        private static string Transform(string target, int shift, bool allowSpace = false)
        {
            if (Math.Abs(shift) < 1 || Math.Abs(shift) > 25)
            {
                throw new ArgumentOutOfRangeException("shift", "Must be greater than 0 and less than 26.");
            }

            if (allowSpace == false)
            {
                Match targetIsValid = inputValidation.Match(target);
                if (!targetIsValid.Success)
                {
                    throw new ArgumentOutOfRangeException("target", "Must be lower case English letters.");
                }
            }
            else
            {
                Match targetIsValid = inputValidationSpacesAllowed.Match(target);
                if (!targetIsValid.Success)
                {
                    throw new ArgumentOutOfRangeException("target", "Must be lower case English letters or spaces.");
                }
            }

            string transformedText = string.Empty;

            foreach (char character in target)
            {
                if (character == ' ')
                {
                    transformedText += ' ';
                    continue;
                }

                char transformedCharacter = (char)(character + shift);
                
                // Wrap around.
                if (transformedCharacter > 'z')
                {
                    transformedCharacter = (char)(transformedCharacter - 26);
                }
                else if (transformedCharacter < 'a')
                {
                    transformedCharacter = (char)(transformedCharacter + 26);
                }

                transformedText += transformedCharacter;
            }

            return transformedText;
        }
    }
}