using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Cryptography_AES {
    public class AESEncryption {
        public static void Main() {
            string originalText = "thisisasecretmessage";

            Console.WriteLine("Enter encryption mode (ECB, CBC, CFB):");
            string? modeInput = Console.ReadLine()?.ToUpper();

            CipherMode mode = modeInput switch {
                "ECB" => CipherMode.ECB,
                "CBC" => CipherMode.CBC,
                "CFB" => CipherMode.CFB,
                _ => CipherMode.CBC
            };

            if (modeInput != "ECB" && modeInput != "CBC" && modeInput != "CFB")
                Console.WriteLine("Invalid mode. Defaulting to CBC.");

            Console.WriteLine("Enter key size (128, 192, 256):");
            if (!int.TryParse(Console.ReadLine(), out int keySize) || (keySize != 128 && keySize != 192 && keySize != 256)) {
                Console.WriteLine("Invalid key size. Defaulting to 256 bits.");
                keySize = 256;
            }

            using Aes aesAlg = Aes.Create();
            aesAlg.KeySize = keySize;
            aesAlg.GenerateKey();
            aesAlg.GenerateIV();

            byte[] key = aesAlg.Key;
            byte[] iv = aesAlg.IV;

            byte[] encryptedText = Encrypt(originalText, key, iv, mode);
            string decryptedText = Decrypt(encryptedText, key, iv, mode);

            Console.WriteLine($"Encrypted Text (Base64): {Convert.ToBase64String(encryptedText)}");
            Console.WriteLine($"Decrypted Text: {decryptedText}");
            Console.WriteLine(originalText == decryptedText ? "Success: Text matches!" : "Error: Mismatch!");
        }

        public static byte[] Encrypt(string plainText, byte[] key, byte[] IV, CipherMode mode) {
            using Aes aes = Aes.Create();
            aes.Key = key;
            aes.Mode = mode;
            aes.Padding = PaddingMode.PKCS7;

            if (mode != CipherMode.ECB)
                aes.IV = IV;

            using ICryptoTransform encryptor = aes.CreateEncryptor();
            using MemoryStream ms = new();
            using CryptoStream cs = new(ms, encryptor, CryptoStreamMode.Write);
            using StreamWriter sw = new(cs);
            sw.Write(plainText);
            sw.Flush();
            cs.FlushFinalBlock();
            return ms.ToArray();
        }

        public static string Decrypt(byte[] cipherText, byte[] key, byte[] IV, CipherMode mode) {
            using Aes aes = Aes.Create();
            aes.Key = key;
            aes.Mode = mode;
            aes.Padding = PaddingMode.PKCS7;

            if (mode != CipherMode.ECB)
                aes.IV = IV;

            using ICryptoTransform decryptor = aes.CreateDecryptor();
            using MemoryStream ms = new(cipherText);
            using CryptoStream cs = new(ms, decryptor, CryptoStreamMode.Read);
            using StreamReader sr = new(cs);
            return sr.ReadToEnd();
        }
    }
}
