using System.Security.Cryptography;
using System.Text;

namespace OpenSslTokenDecryptor
{
    public class NodeJsSerializerMessageDigestCreator : IDigestCreator
    {
        public string Digest { get; private set;}
        
        public NodeJsSerializerMessageDigestCreator(string message, byte[] signingKey)
        {
            Digest = SignMessage(message, signingKey);
        }

        private static string SignMessage(string message, byte[] signingKey)
        {
            var hmacsha1 = new HMACSHA1(signingKey);

            var messageBytes = Encoding.UTF8.GetBytes(message);

            var hashmessage = hmacsha1.ComputeHash(messageBytes);

            var base64Message = System.Convert.ToBase64String(hashmessage);

            return base64Message.Replace("+", "-").Replace("/", "_");
        }
    }
}
