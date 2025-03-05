namespace Cryptography_AES
{
    using System;

    public abstract class AESMode(byte[] key) {
        protected const int BlockSize = 16;
        protected AES aes = new(key);

        public abstract byte[] Encrypt(byte[] plaintext);
        public abstract byte[] Decrypt(byte[] ciphertext);

        protected static byte[] Pad(byte[] data) {
            int paddingLength = BlockSize - (data.Length % BlockSize);
            byte[] padded = new byte[data.Length + paddingLength];
            Array.Copy(data, padded, data.Length);
            for (int i = data.Length; i < padded.Length; i++) {
                padded[i] = (byte)paddingLength;
            }
            return padded;
        }

        protected static byte[] Unpad(byte[] data) {
            int paddingLength = data[^1];
            byte[] unpadded = new byte[data.Length - paddingLength];
            Array.Copy(data, unpadded, unpadded.Length);
            return unpadded;
        }

        protected static byte[] Xor(byte[] a, byte[] b) {
            byte[] result = new byte[a.Length];
            for (int i = 0; i < a.Length; i++) {
                result[i] = (byte)(a[i] ^ b[i]);
            }
            return result;
        }
    }

}
