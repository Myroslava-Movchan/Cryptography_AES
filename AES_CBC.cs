using System.Runtime.Intrinsics.Arm;

namespace Cryptography_AES {
    public class AES_CBC : AESMode {
        private readonly byte[] iv;
        public AES_CBC(byte[] key, byte[] iv) : base(key) {
            if (iv == null || iv.Length != BlockSize) throw new ArgumentException("Invalid IV size");
            this.iv = iv;
        }

        public override byte[] Encrypt(byte[] plaintext) {
            plaintext = Pad(plaintext);
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] prevBlock = iv;

            for (int i = 0; i < plaintext.Length; i += BlockSize) {
                byte[] block = new byte[BlockSize];
                Array.Copy(plaintext, i, block, 0, BlockSize);
                block = Xor(block, prevBlock);
                byte[] encryptedBlock = aes.Encrypt(block);
                Array.Copy(encryptedBlock, 0, ciphertext, i, BlockSize);
                prevBlock = encryptedBlock;
            }
            return ciphertext;
        }

        public override byte[] Decrypt(byte[] ciphertext) {
            byte[] plaintext = new byte[ciphertext.Length];
            byte[] prevBlock = iv;

            for (int i = 0; i < ciphertext.Length; i += BlockSize) {
                byte[] block = new byte[BlockSize];
                Array.Copy(ciphertext, i, block, 0, BlockSize);
                byte[] decryptedBlock = aes.Decrypt(block);
                decryptedBlock = Xor(decryptedBlock, prevBlock);
                Array.Copy(decryptedBlock, 0, plaintext, i, BlockSize);
                prevBlock = block;
            }
            return Unpad(plaintext);
        }
    }

}
