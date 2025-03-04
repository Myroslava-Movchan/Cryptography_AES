namespace Cryptography_AES
{
    public class AES_ECB(byte[] key) : AESMode(key) {
        protected override byte[] EncryptBlock(byte[] block) => aes.Encrypt(block);
        protected override byte[] DecryptBlock(byte[] block) => aes.Decrypt(block);
    }
}
