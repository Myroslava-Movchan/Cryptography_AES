namespace Cryptography_AES
{
    public static class PaddingHelper {
        public static byte[] Pad(byte[] data, int blockSize) {
            int paddingLength = blockSize - (data.Length % blockSize);
            byte[] paddedData = new byte[data.Length + paddingLength];
            Array.Copy(data, paddedData, data.Length);
            for (int i = data.Length; i < paddedData.Length; i++) {
                paddedData[i] = (byte)paddingLength;
            }
            return paddedData;
        }

        public static byte[] Unpad(byte[] data, int blockSize) {
            int paddingLength = data[^1];
            if (paddingLength <= 0 || paddingLength > blockSize) {
                throw new ArgumentException("Invalid padding detected.");
            }
            for (int i = data.Length - paddingLength; i < data.Length; i++) {
                if (data[i] != paddingLength) throw new ArgumentException("Invalid padding detected.");
            }
            byte[] unpaddedData = new byte[data.Length - paddingLength];
            Array.Copy(data, unpaddedData, unpaddedData.Length);
            return unpaddedData;
        }
    }

}
