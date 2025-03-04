using System.Runtime.Intrinsics.Arm;

namespace Cryptography_AES
{
    public class AES_ECB(byte[] key) : AESMode(key) {
        public override byte[] Encrypt(byte[] plaintext) {
            plaintext = Pad(plaintext);
            byte[] ciphertext = new byte[plaintext.Length];

            for (int i = 0; i < plaintext.Length; i += BlockSize) {
                byte[] block = new byte[BlockSize];
                Array.Copy(plaintext, i, block, 0, BlockSize);
                byte[] encryptedBlock = aes.Encrypt(block);
                Array.Copy(encryptedBlock, 0, ciphertext, i, BlockSize);
            }
            return ciphertext;
        }

        public override byte[] Decrypt(byte[] ciphertext) {
            byte[] plaintext = new byte[ciphertext.Length];

            for (int i = 0; i < ciphertext.Length; i += BlockSize) {
                byte[] block = new byte[BlockSize];
                Array.Copy(ciphertext, i, block, 0, BlockSize);
                byte[] decryptedBlock = aes.Decrypt(block);
                Array.Copy(decryptedBlock, 0, plaintext, i, BlockSize);
            }
            return Unpad(plaintext);
        }
    }

}
