using System.Text;

namespace OpenSslTokenDecryptor
{
    public class NodeJsSerializerTokenProcessor
    {
        public string Process(string token, string encryptKey, string validateKey)
        {
            try
            {
                var password = Encoding.UTF8.GetBytes(encryptKey);

                ITokenParser tokenParser = new NodeJsSerializerTokenParser(token);

                IKeyGenerator keyHolder = new OpenSsl1_0_0KeyGenerator(password, tokenParser.Salt);

                IDecryptor decryptor = new NodeJsSerializerTokenDecryptor(tokenParser.Data, keyHolder);

                IMessageParser messageParser = new NodeJsSerializerMessageParser(decryptor.DecryptedData);

                var signingKey = Encoding.UTF8.GetBytes(validateKey + messageParser.Nonce);

                IDigestCreator digestCreator = new NodeJsSerializerMessageDigestCreator(messageParser.Message, signingKey);

                return tokenParser.Digest == digestCreator.Digest ? messageParser.Message : string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }
    }
}

