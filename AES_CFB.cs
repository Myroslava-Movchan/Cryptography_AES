namespace Cryptography_AES {
    public class AES_CFB : AESMode {
        private byte[] iv;

        public AES_CFB(byte[] key, byte[] iv) : base(key) {
            if (iv.Length != BlockSize) throw new ArgumentException("Invalid IV size.");
            this.iv = iv;
        }

        protected override byte[] EncryptBlock(byte[] block) {
            byte[] encrypted = aes.Encrypt(iv);
            for (int i = 0; i < BlockSize; i++) block[i] ^= encrypted[i];
            iv = block;
            return block;
        }

        protected override byte[] DecryptBlock(byte[] block) {
            byte[] encrypted = aes.Encrypt(iv);
            byte[] decrypted = new byte[BlockSize];
            for (int i = 0; i < BlockSize; i++) decrypted[i] = (byte)(block[i] ^ encrypted[i]);
            iv = block;
            return decrypted;
        }
    }
}
