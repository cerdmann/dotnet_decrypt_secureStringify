namespace OpenSslTokenDecryptor
{
    public class NodeJsSerializerMessageParser : IMessageParser
    {
        public string Nonce { get; private set; }
        public string Message { get; private set; }    

        public NodeJsSerializerMessageParser(string message)
        {
            Split(message);
        }

        private void Split(string message)
        {
            Nonce = message.Substring(0, 8);
            Message = message.Substring(8);
        }
    }
}