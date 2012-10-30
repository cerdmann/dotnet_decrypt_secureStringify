using System.Security.Cryptography;
using System.Text;

namespace OpenSslTokenDecryptor
{
    public class NodeJsSerializerTokenDecryptor : IDecryptor
    {
        public string DecryptedData { get; private set; }

        public NodeJsSerializerTokenDecryptor(byte[] dataToDecrypt, IKeyGenerator keyHolder)
        {
            DecryptedData = UseAesToDecrypt(dataToDecrypt, keyHolder.Key, keyHolder.Iv);
        }

        private static string UseAesToDecrypt(byte[] encryptedData, byte[] key, byte[] iv)
        {
            string decryptedData;

            using (var aesProvider = new AesCryptoServiceProvider())
            {
                aesProvider.Key = key;
                aesProvider.IV = iv;
                aesProvider.Mode = CipherMode.CBC;
                aesProvider.Padding = PaddingMode.PKCS7;

                using (var decryptor = aesProvider.CreateDecryptor())
                {
                    var result = decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
                    decryptedData = Encoding.UTF8.GetString(result, 0, result.Length);
                }
            }

            return decryptedData;
        }
    }
}
