using System;
using System.Security.Cryptography;

namespace OpenSslTokenDecryptor
{
    class OpenSsl1_0_0KeyGenerator : IKeyGenerator
    {
        // For aes-256:
        //
        // Hash0 = ''
        // Hash1 = MD5(Hash0 + Password + Salt)
        // Hash2 = MD5(Hash1 + Password + Salt)
        // Hash3 = MD5(Hash2 + Password + Salt)
        // Hash4 = MD5(Hash3 + Password + Salt)
        //
        // Key = Hash1 + Hash2
        // IV = Hash3 + Hash4 (But openssl 1.0.0 only shows a 16 bit IV)
        //
        public byte[] Key { get; private set; }
        public byte[] Iv { get; private set; }

        public OpenSsl1_0_0KeyGenerator(byte[] password, byte[] salt)
        {
            var startingHash = (new byte[0]);
            var hash1 = ComputeHash(startingHash, password, salt);
            var hash2 = ComputeHash(hash1, password, salt);
            var hash3 = ComputeHash(hash2, password, salt);
            //var hash4 = ComputeHash(hash3, password, salt);

            Key = MergeHash(hash1, hash2);
            //Iv = MergeHash(hash3, hash4);
            Iv = hash3;
        }

        private static byte[] ComputeHash(byte[] startingBytes, byte[] password, byte[] salt)
        {
            using (var md5 = MD5.Create())
            {
                var holderLength = startingBytes.Length + password.Length + salt.Length;
                var holder = new byte[holderLength];

                Buffer.BlockCopy(startingBytes, 0, holder, 0, startingBytes.Length);
                Buffer.BlockCopy(password, 0, holder, startingBytes.Length, password.Length);
                Buffer.BlockCopy(salt, 0, holder, startingBytes.Length + password.Length, salt.Length);

                var key = md5.ComputeHash(holder);

                md5.Clear();
                return key;
            }

        }

        private static byte[] MergeHash(byte[] hash1, byte[] hash2)
        {
            var holderLength = hash1.Length + hash2.Length;
            var holder = new byte[holderLength];

            Buffer.BlockCopy(hash1, 0, holder, 0, hash1.Length);
            Buffer.BlockCopy(hash2, 0, holder, hash1.Length, hash2.Length);

            return holder;
        }



    }
}
