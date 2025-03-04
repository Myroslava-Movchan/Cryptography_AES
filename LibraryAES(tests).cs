using System;
using System.Linq;
using System.Security.Cryptography;
using Xunit;

namespace Tests {
    public class AESTests2 {
        [Theory]
        [InlineData("ECB", "2B7E151628AED2A6ABF7158809CF4F3C",
            "3AD77BB40D7A3660A89ECAF32466EF97F5D3D58503B9699DE785895A96FDBAAF43B1CD7F598ECE23881B00E3ED0306887B0C785E27E8AD3F8223207104725DD4")]
        [InlineData("ECB", "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B",
            "BD334F1D6E45F25FF712A214571FA5CC974104846D0AD3AD7734ECB3ECEE4EEFEF7AFD2270E2E60ADCE0BA2FACE6444E9A4B41BA738D6C72FB16691603C18E0E")]
        [InlineData("ECB", "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4",
            "F3EED1BDB5D2A03C064B5A7E3DB181F8591CCB10D410ED26DC5BA74A31362870B6ED21B99CA6F4F9F153E7B1BEAFED1D23304B7A39F9F3FF067D8D8F9E24ECC7")]
        [InlineData("CBC", "2B7E151628AED2A6ABF7158809CF4F3C",
            "7649ABAC8119B246CEE98E9B12E9197D5086CB9B507219EE95DB113A917678B273BED6B8E3C1743B7116E69E222295163FF1CAA1681FAC09120ECA307586E1A7")]
        [InlineData("CBC", "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B",
            "4F021DB243BC633D7178183A9FA071E8B4D9ADA9AD7DEDF4E5E738763F69145A571B242012FB7AE07FA9BAAC3DF102E008B0E27988598881D920A9E64F5615CD")]
        [InlineData("CBC", "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4",
            "F58C4C04D6E5F1BA779EABFB5F7BFBD69CFC4E967EDB808D679F777BC6702C7D39F23369A9D9BACFA530E26304231461B2EB05E2C39BE9FCDA6C19078C6A9D1B")]
        [InlineData("CFB", "2B7E151628AED2A6ABF7158809CF4F3C",
            "3B3FD92EB72DAD20333449F8E83CFB4AC8A64537A0B3A93FCDE3CDAD9F1CE58B26751F67A3CBB140B1808CF187A4F4DFC04B05357C5D1C0EEAC4C66F9FF7F2E6")]
        [InlineData("CFB", "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B",
            "CDC80D6FDDF18CAB34C25909C99A417467CE7F7F81173621961A2B70171D3D7A2E1E8A1DD59B88B1C8E60FED1EFAC4C9C05F9F9CA9834FA042AE8FBA584B09FF")]
        [InlineData("CFB", "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4",
            "DC7E84BFDA79164B7ECD8486985D386039FFED143B28B1C832113C6331E5407BDF10132415E54B92A13ED0A8267AE2F975A385741AB9CEF82031623D55B1E471")]
        public void AESTestVectors(string mode, string keyHex, string expectedCiphertextHex) {
            byte[] plaintext = ConvertHexStringToByteArray("6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710");
            byte[] key = ConvertHexStringToByteArray(keyHex);
            byte[] iv = ConvertHexStringToByteArray("000102030405060708090A0B0C0D0E0F");
            byte[] expectedCiphertext = ConvertHexStringToByteArray(expectedCiphertextHex);

            using Aes aesAlg = Aes.Create();
            aesAlg.Key = key;
            aesAlg.IV = iv;

            aesAlg.Mode = mode switch {
                "ECB" => CipherMode.ECB,
                "CBC" => CipherMode.CBC,
                "CFB" => CipherMode.CFB,
                _ => throw new ArgumentException("Invalid mode")
            };

            aesAlg.Padding = PaddingMode.None;

            using ICryptoTransform encryptor = aesAlg.CreateEncryptor();
            byte[] actualCiphertext = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
            Assert.Equal(expectedCiphertext, actualCiphertext);

            // Test decryption
            using ICryptoTransform decryptor = aesAlg.CreateDecryptor();
            byte[] decryptedText = decryptor.TransformFinalBlock(actualCiphertext, 0, actualCiphertext.Length);
            Assert.Equal(plaintext, decryptedText);
        }

        private byte[] ConvertHexStringToByteArray(string hex) {
            int length = hex.Length;
            byte[] data = new byte[length / 2];
            for (int i = 0; i < length; i += 2)
                data[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return data;
        }
    }
}
