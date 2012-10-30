using System;
using System.Text;

namespace OpenSslTokenDecryptor
{
    public class NodeJsSerializerTokenParser : ITokenParser
    {
        public string Digest { get; private set;}
        public byte[] Data { get; private set; }
        public byte[] Salt { get; private set; }

        public NodeJsSerializerTokenParser(string token)
        {
            var decodedToken = Decode(token);
            Split(decodedToken);
        }

        private void Split(string decodedToken)
        {
            var expectedDigest = decodedToken.Substring(0, 28);
            var nonceCrypt = decodedToken.Substring(28, 8);
            var data = decodedToken.Substring(36);

            Digest = expectedDigest;
            Salt = Encoding.UTF8.GetBytes(nonceCrypt);
            Data = HexStringToByteArray(data);
        }

        private static string Decode(string token)
        {
            return Uri.UnescapeDataString(token);
        }

        private static byte[] HexStringToByteArray(String hex)
        {
            var numberChars = hex.Length;
            var bytes = new byte[numberChars / 2];
            for (var i = 0; i < numberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }
    }
}
