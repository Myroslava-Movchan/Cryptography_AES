namespace Cryptography_AES
{
    public abstract class AESMode(byte[] key) {
        protected readonly AES aes = new(key);
        protected const int BlockSize = 16;

        public byte[] Encrypt(byte[] plaintext) {
            plaintext = PaddingHelper.Pad(plaintext, BlockSize);
            return ProcessBlocks(plaintext, EncryptBlock);
        }

        public byte[] Decrypt(byte[] ciphertext) {
            byte[] plaintext = ProcessBlocks(ciphertext, DecryptBlock);
            return PaddingHelper.Unpad(plaintext, BlockSize);
        }

        protected abstract byte[] EncryptBlock(byte[] block);
        protected abstract byte[] DecryptBlock(byte[] block);

        private byte[] ProcessBlocks(byte[] data, Func<byte[], byte[]> blockProcessor) {
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i += BlockSize) {
                byte[] block = new byte[BlockSize];
                Array.Copy(data, i, block, 0, BlockSize);
                byte[] processedBlock = blockProcessor(block);
                Array.Copy(processedBlock, 0, result, i, BlockSize);
            }
            return result;
        }
    }

}
