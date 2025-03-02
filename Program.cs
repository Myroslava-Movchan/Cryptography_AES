using System.Security.Cryptography;
using System.Text;

public class AESEncryption
{
    public static void Main(string[] args)
    {
        string originalText = "thisisasecretmessage";

        Console.WriteLine("Enter encryption mode (ECB, CBC, CFB):");
        string? mode = Console.ReadLine()?.ToUpper();

        using (Aes aesAlg = Aes.Create())
        {
            byte[] key = aesAlg.Key;
            byte[] iv = aesAlg.IV;

            AESEncryption aesEncryption = new AESEncryption();

            byte[] encryptedText = aesEncryption.Encrypt(originalText, key, iv, mode);

            byte[] cipherBytes = encryptedText;

            string decryptedText = aesEncryption.Decrypt(cipherBytes, key, iv, mode);
            Console.WriteLine("Decrypted Text: " + decryptedText);

            if (originalText == decryptedText)
            {
                Console.WriteLine("The original text and decrypted text are the same.");
            }
            else
            {
                Console.WriteLine("The original text and decrypted text are different.");
            }
        }
    }

    public byte[] Encrypt(string plainText, byte[] key, byte[] IV, string mode)
    {
        byte[] encrypted;

        using (Aes aes = Aes.Create())
        {
            aes.Key = key;

            if (mode == "ECB")
            {
                aes.Mode = CipherMode.ECB;
                aes.IV = new byte[16];
            }
            else if (mode == "CBC")
            {
                aes.Mode = CipherMode.CBC;
                aes.IV = IV;
            }
            else if (mode == "CFB")
            {
                aes.Mode = CipherMode.CFB;
                aes.IV = IV;
            }
            else
            {
                Console.WriteLine("using usual AES");
            }

            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }
        }
        return encrypted;
    }

    public string Decrypt(byte[] cipherText, byte[] key, byte[] IV, string mode)
    {
        string decrypted;
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;

            if (mode == "ECB")
            {
                aes.Mode = CipherMode.ECB;
            }
            else if (mode == "CBC")
            {
                aes.Mode = CipherMode.CBC;
                aes.IV = IV;
            }
            else if (mode == "CFB")
            {
                aes.Mode = CipherMode.CFB;
                aes.IV = IV;
            }
            else
            {
                Console.WriteLine("Invalid mode, using AES CBC");
                aes.Mode = CipherMode.CBC;
                aes.IV = IV;
            }
            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            using (MemoryStream msDecrypt = new MemoryStream(cipherText))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        decrypted = srDecrypt.ReadToEnd();
                    }
                }
            }
        }
        return decrypted;
    }

    public static byte[] HexStringToByteArray(string hex)
    {
        return Enumerable.Range(0, hex.Length / 2)
            .Select(x => Convert.ToByte(hex.Substring(x * 2, 2), 16))
            .ToArray();
    }
}
