using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Web;
using System.Web.Mvc;
using System.Xml;

namespace Cryptography101.Controllers
{
    public class XmlController : Controller
    {
        const string SenderThumbprint = "74e5939279c4242705ff24d651eb322768279959";
        const string RecipientThumbprint = "38782664497a8f4f530ef7445e95d6e1889fa734";

        public ActionResult Index()
        {
            var xml = new XmlDocument();
            xml.LoadXml("<message>Hello World</message>");

            var model = new XmlModel();
            model.PlainText = XmlToString(xml);
            model.RecipientThumbprint = RecipientThumbprint;
            model.SenderThumbprint = SenderThumbprint;
            return View(model);
        }

        [HttpPost]
        public ActionResult Index(XmlModel model)
        {
            if (model.Action == "encrypt")
            {
                var recipientCertificate = LoadCertificate(model.RecipientThumbprint);
                var signingCertificate = LoadCertificate(model.SenderThumbprint);
                var xmlDocument = new XmlDocument();
                xmlDocument.LoadXml(model.PlainText);

                var elementToEncrypt = xmlDocument.GetElementsByTagName("message")[0] as XmlElement;
                var encryptedXml = new EncryptedXml();

                // Encrypt the element.
                var encryptedElement = encryptedXml.Encrypt(elementToEncrypt, recipientCertificate);
                EncryptedXml.ReplaceElement(elementToEncrypt, encryptedElement, false);

                // Sign the document
                var signedXml = new SignedXml(xmlDocument) { SigningKey = signingCertificate.PrivateKey };
                var reference = new Reference { Uri = string.Empty };

                var transform = new XmlDsigC14NTransform();
                reference.AddTransform(transform);

                var envelope = new XmlDsigEnvelopedSignatureTransform();
                reference.AddTransform(envelope);
                signedXml.AddReference(reference);

                var keyInfo = new KeyInfo();
                keyInfo.AddClause(new KeyInfoX509Data(signingCertificate));
                signedXml.KeyInfo = keyInfo;
                signedXml.ComputeSignature();

                var xmlDigitalSignature = signedXml.GetXml();
                xmlDocument.DocumentElement.AppendChild(xmlDocument.ImportNode(xmlDigitalSignature, true));

                model.PlainText = "";
                model.Envelope = XmlToString(xmlDocument);
            }
            else if (model.Action == "decrypt")
            {
                var xmlDocument = new XmlDocument();
                xmlDocument.LoadXml(model.Envelope);

                // Validate the signature
                var signedXml = new SignedXml(xmlDocument);
                var nodeList = xmlDocument.GetElementsByTagName("Signature");

                if (nodeList.Count <= 0)
                {
                    throw new Exception("No signature found.");
                }

                signedXml.LoadXml((XmlElement)nodeList[0]);
                AsymmetricAlgorithm signingKey;

                if (!signedXml.CheckSignatureReturningKey(out signingKey))
                {
                    throw new Exception("Invalid Signature");
                }
                else
                {                    
                    IEnumerable<X509Certificate2> keyInfoCertificates =
                        signedXml.KeyInfo.OfType<KeyInfoX509Data>()
                            .SelectMany(x => x.Certificates.Cast<X509Certificate2>());
                    var signingCertificate = keyInfoCertificates.FirstOrDefault(x => x.PublicKey.Key == signingKey);
                    if (signingCertificate == null)
                    {
                        throw new Exception("Signing certificate not found in KeyInfo.");
                    }
                    model.SenderSubject = signingCertificate.Subject;
                }

                var encryptedXml = new EncryptedXml(xmlDocument);
                encryptedXml.DecryptDocument();

                model.Envelope = "";
                model.PlainText = XmlToString(xmlDocument);
            }

            ModelState.Clear();
            model.RecipientThumbprint = RecipientThumbprint;
            model.SenderThumbprint = SenderThumbprint;
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

        private static string XmlToString(XmlNode xml)
        {
            using (StringWriter sw = new StringWriter(CultureInfo.InvariantCulture))
            {
                using (XmlTextWriter xw = new XmlTextWriter(sw)
                {
                    Formatting = Formatting.Indented,
                    Indentation = 2,
                    IndentChar = ' '
                })
                {
                    xml.WriteTo(xw);
                }

                sw.Flush();
                return sw.ToString();
            }
        }
    }

    public class XmlModel
    {
        public string Action { get; set; }

        [DisplayName("Plain Text")]
        [AllowHtml]
        public string PlainText { get; set; }

        [DisplayName("Signed Envelope")]
        [AllowHtml]
        public string Envelope { get; set; }

        [DisplayName("Recipient Certificate Thumbprint")]
        public string RecipientThumbprint { get; set; }

        [DisplayName("Sender Certificate Thumbprint")]
        public string SenderThumbprint { get; set; }

        public string SenderSubject { get; set; }
    }
}