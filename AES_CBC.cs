namespace Cryptography_AES
{
    public class AES_CBC : AESMode {
        private byte[] iv;

        public AES_CBC(byte[] key, byte[] iv) : base(key) {
            if (iv.Length != BlockSize) throw new ArgumentException("Invalid IV size.");
            this.iv = iv;
        }

        protected override byte[] EncryptBlock(byte[] block) {
            for (int i = 0; i < BlockSize; i++) block[i] ^= iv[i];
            byte[] encrypted = aes.Encrypt(block);
            iv = encrypted;
            return encrypted;
        }

        protected override byte[] DecryptBlock(byte[] block) {
            byte[] decrypted = aes.Decrypt(block);
            for (int i = 0; i < BlockSize; i++) decrypted[i] ^= iv[i];
            iv = block;
            return decrypted;
        }
    }

}
