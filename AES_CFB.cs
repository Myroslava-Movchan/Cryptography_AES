namespace Cryptography_AES {
    public class AES_CFB : AESMode {
        private readonly byte[] iv;
        public AES_CFB(byte[] key, byte[] iv) : base(key) {
            if (iv == null || iv.Length != BlockSize) throw new ArgumentException("Invalid IV size");
            this.iv = iv;
        }

        public override byte[] Encrypt(byte[] plaintext) {
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] prevBlock = iv;

            for (int i = 0; i < plaintext.Length; i += BlockSize) {
                byte[] encryptedBlock = aes.Encrypt(prevBlock);
                byte[] block = new byte[BlockSize];
                int bytesToProcess = Math.Min(BlockSize, plaintext.Length - i);
                Array.Copy(plaintext, i, block, 0, bytesToProcess);
                byte[] cipherBlock = Xor(block, encryptedBlock);
                Array.Copy(cipherBlock, 0, ciphertext, i, bytesToProcess);
                prevBlock = cipherBlock;
            }
            return ciphertext;
        }

        public override byte[] Decrypt(byte[] ciphertext) {
            byte[] plaintext = new byte[ciphertext.Length];
            byte[] prevBlock = iv;

            for (int i = 0; i < ciphertext.Length; i += BlockSize) {
                byte[] encryptedBlock = aes.Encrypt(prevBlock);
                byte[] cipherBlock = new byte[BlockSize];
                int bytesToProcess = Math.Min(BlockSize, ciphertext.Length - i);
                Array.Copy(ciphertext, i, cipherBlock, 0, bytesToProcess);
                byte[] decryptedBlock = Xor(cipherBlock, encryptedBlock);
                Array.Copy(decryptedBlock, 0, plaintext, i, bytesToProcess);
                prevBlock = cipherBlock;
            }
            return plaintext;
        }
    }

}
