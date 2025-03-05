using System.Security.Cryptography;

namespace Cryptography_AES {
    public static class RandKeyGen {
        public static byte[] GenerateKey(int keySizeInBits) {
            if (keySizeInBits != 128 && keySizeInBits != 192 && keySizeInBits != 256) {
                throw new ArgumentException("Key size must be 128, 192, or 256 bits.");
            }

            int keySizeInBytes = keySizeInBits / 8;
            byte[] key = new byte[keySizeInBytes];

            using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) {
                rng.GetBytes(key);
            }

            return key;
        }
    }
}
