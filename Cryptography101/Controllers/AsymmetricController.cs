using System;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Pkcs;
using System.Text;
using System.Web.Mvc;

namespace Cryptography101.Controllers
{
    public class AsymmetricController : Controller
    {
        const string EncryptAndDecryptThumbprint = "38782664497a8f4f530ef7445e95d6e1889fa734";
        const string SenderThumbprint = "74e5939279c4242705ff24d651eb322768279959";
        const string RecipientThumbprint = "38782664497a8f4f530ef7445e95d6e1889fa734";

        public ActionResult Index()
        {
            var model = new AsymmetricModel();
            model.RecipientThumbprint = EncryptAndDecryptThumbprint;
            return View(model);
        }

        [HttpPost]
        public ActionResult Index(AsymmetricModel model)
        {
            if (model.Action == "encrypt")
            {
                var plainTextAsBytes = Encoding.Unicode.GetBytes(model.PlainText);
                var recipientCertificate = LoadCertificate(model.RecipientThumbprint);
                var encryptionProvider =
                    (RSACryptoServiceProvider)recipientCertificate.PublicKey.Key;

                byte[] cipherTextAsBytes = encryptionProvider.Encrypt(plainTextAsBytes, true);

                model.CipherText = Convert.ToBase64String(cipherTextAsBytes);
                model.PlainText = string.Empty;
            }
            else if (model.Action == "decrypt")
            {
                var cipherTextAsBytes = Convert.FromBase64String(model.CipherText);
                var recipientCertificate = LoadCertificate(model.RecipientThumbprint);
                var decryptionProvider =
                    (RSACryptoServiceProvider)recipientCertificate.PrivateKey;

                byte[] plainTextAsBytes = decryptionProvider.Decrypt(cipherTextAsBytes, true);

                model.CipherText = string.Empty;
                model.PlainText = Encoding.Unicode.GetString(plainTextAsBytes);
            }

            ModelState.Clear();
            return View(model);
        }

        public ActionResult SignAndEncrypt()
        {
            var model = new SignedAsymmetricModel();
            model.RecipientThumbprint = RecipientThumbprint;
            model.SenderThumbprint = SenderThumbprint;

            return View(model);
        }

        [HttpPost]
        public ActionResult SignAndEncrypt(SignedAsymmetricModel model)
        {
            if (model.Action == "encrypt")
            {
                var plainTextAsBytes = Encoding.Unicode.GetBytes(model.PlainText);
                var recipientCertificate = LoadCertificate(model.RecipientThumbprint);
                var signingCertificate = LoadCertificate(model.SenderThumbprint);

                // Sign message
                var signatureContentInfo = new ContentInfo(plainTextAsBytes);
                var signedCms = new SignedCms(signatureContentInfo);
                var cmsSigner = new CmsSigner(signingCertificate);
                signedCms.ComputeSignature(cmsSigner);
                var signedMessageAsBytes = signedCms.Encode();

                // Encrypt
                var encryptedContentInfo = new ContentInfo(signedMessageAsBytes);
                var envelopedCms = new EnvelopedCms(encryptedContentInfo);
                var cmsRecipient = new CmsRecipient(recipientCertificate);
                envelopedCms.Encrypt(cmsRecipient);
                var envelopeAsBytes = envelopedCms.Encode();

                model.Envelope = Convert.ToBase64String(envelopeAsBytes);
                model.PlainText = string.Empty;
            }
            else if (model.Action == "decrypt")
            {
                // Decrypt
                var cipherTextAsBytes = Convert.FromBase64String(model.Envelope);
                var envelopedCms = new EnvelopedCms();
                envelopedCms.Decode(cipherTextAsBytes);
                envelopedCms.Decrypt();
                var encodedSignedCMS = envelopedCms.Encode();
                var signedCms = new SignedCms();
                signedCms.Decode(encodedSignedCMS);
                signedCms.CheckSignature(true);

                var plainTextAsBytes = signedCms.ContentInfo.Content;
                model.PlainText = UnicodeEncoding.Unicode.GetString(plainTextAsBytes);
                model.SenderSubject = signedCms.SignerInfos[0].Certificate.Subject;
                model.Envelope = string.Empty;
            }
            model.RecipientThumbprint = RecipientThumbprint;
            model.SenderThumbprint = SenderThumbprint;
            ModelState.Clear();
            return View(model);
        }


        static X509Certificate2 LoadCertificate(string thumbprint)
        {
            var certificateStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            certificateStore.Open(OpenFlags.ReadOnly);
            var searchResults =
            certificateStore.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);

            if (searchResults.Count != 1)
            {
                throw new ArgumentException("Cannot find individual certificate with the thumbprint specified.", "thumbprint");
            }

            certificateStore.Close();
            return searchResults[0];
        }
    }


    public class AsymmetricModel
    {
        public string Action { get; set; }

        [DisplayName("Plain Text")]
        public string PlainText { get; set; }

        [DisplayName("Cipher Text")]
        public string CipherText { get; set; }

        public string Signature { get; set; }

        [DisplayName("Recipient Certificate Thumbprint")]
        public string RecipientThumbprint { get; set; }
    }

    public class SignedAsymmetricModel
    {
        public string Action { get; set; }

        [DisplayName("Plain Text")]
        public string PlainText { get; set; }

        [DisplayName("Signed Envelope")]
        public string Envelope { get; set; }

        [DisplayName("Recipient Certificate Thumbprint")]
        public string RecipientThumbprint { get; set; }

        [DisplayName("Sender Certificate Thumbprint")]
        public string SenderThumbprint { get; set; }

        public string SenderSubject { get; set; }
    }
}