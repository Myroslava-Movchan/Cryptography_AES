using System.Text;

namespace Cryptography_AES {
    public class AESEncryption {
        public static void Main() {
            string originalText = "thisisasecretmessage";

            Console.WriteLine("Enter encryption mode (ECB, CBC, CFB):");
            string? modeInput = Console.ReadLine()?.ToUpper();

            if (modeInput != "ECB" && modeInput != "CBC" && modeInput != "CFB")
                Console.WriteLine("Invalid mode. Defaulting to CBC.");

            Console.WriteLine("Enter key size (128, 192, 256):");
            if (!int.TryParse(Console.ReadLine(), out int keySize) || (keySize != 128 && keySize != 192 && keySize != 256)) {
                Console.WriteLine("Invalid key size. Defaulting to 256 bits.");
                keySize = 256;
            }

            byte[] key = RandKeyGen.GenerateKey(keySize);
            byte[] iv = RandKeyGen.GenerateKey(128);

            AESMode aes = modeInput switch {
                "ECB" => new AES_ECB(key),
                "CBC" => new AES_CBC(key, iv),
                "CFB" => new AES_CFB(key, iv),
                _ => new AES_CBC(key, iv)
            };

            byte[] encryptedText = aes.Encrypt(Encoding.UTF8.GetBytes(originalText));
            string decryptedText = Encoding.UTF8.GetString(aes.Decrypt(encryptedText));

            Console.WriteLine($"Encrypted Text (Base64): {Convert.ToBase64String(encryptedText)}");
            Console.WriteLine($"Decrypted Text: {decryptedText}");
            Console.WriteLine(originalText == decryptedText ? "Success: Text matches!" : "Error: Mismatch!");
        }
    }
}
