using Microsoft.VisualStudio.TestTools.UnitTesting;
using OpenSslTokenDecryptor;

namespace OpenSslTokenDecryptorTests
{
    [TestClass]
    public class NodeJsSerializerTokenProcessorTests
    {
        private const string EncryptionSecret = "encryption secret";
        private const string SigningSecret = "signing secret";

        [TestMethod]
        public void AsATokenReceiverIWantToDecryptATokenEncryptedByTheNodeJsSerializer()
        {
            const string token =
                "5W2A_JmyNfOH7g6T3E18u1PJkMs%3DWNRv9wa6d33721fd952b9b0cc12df1151c774ef70438e32a9957f8646c58adf2929bb5c707318c2272bd50122a23153b7f7783ff5e3d82ae3a6e621eb8d5501676470fe0";

            var processor = new NodeJsSerializerTokenProcessor();

            var result = processor.Process(token, EncryptionSecret, SigningSecret);

            Assert.AreEqual("[\"My User Name\",\"1\",1351613259772,\"blah\"]", result);
        }

        [TestMethod]
        public void AsATokenReceiverIWantToEnsureThatIDoNotProcessAMessageThatFailsDigestMatch()
        {
            const string token =
                "5w2A_JmyNfOH7g6T3E18u1PJkMs%3DWNRv9wa6d33721fd952b9b0cc12df1151c774ef70438e32a9957f8646c58adf2929bb5c707318c2272bd50122a23153b7f7783ff5e3d82ae3a6e621eb8d5501676470fe0";

            var processor = new NodeJsSerializerTokenProcessor();

            var result = processor.Process(token, EncryptionSecret, SigningSecret);

            Assert.AreEqual(string.Empty, result);
        }
        [TestMethod]
        public void AsATokenReceiverIWantToEnsureThatIReceiveNothingForABadEncryptionString()
        {
            const string token =
                "";

            var processor = new NodeJsSerializerTokenProcessor();

            var result = processor.Process(token, EncryptionSecret, SigningSecret);

            Assert.AreEqual(string.Empty, result);
        }
    }
}