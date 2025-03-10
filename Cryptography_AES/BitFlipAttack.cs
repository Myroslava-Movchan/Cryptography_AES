using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

class AESCBCBitFlippingAttack {
    static readonly byte[] Key = ConvertHexStringToByteArray("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4");
    static readonly byte[] IV = ConvertHexStringToByteArray("000102030405060708090A0B0C0D0E0F");

    static void Main(string[] args) {
        string firstBlock = "unimportantblock";
        string secondBlock = "amount=100......";
        string thirdBlock = "role=guest";
        string originalMessage = firstBlock + secondBlock + thirdBlock;

        byte[] encryptedMessage = EncryptMessage(originalMessage, Key, IV);
        Console.WriteLine("Original encrypted message:");
        PrintByteArray(encryptedMessage);

        List<byte[]> bitFlips = GetBitFlippedVariants(encryptedMessage);
        List<byte[]> roleFlips = GetRoleFlippedVariants(encryptedMessage);

        Console.WriteLine("\n\nTesting Bit Flips...");
        TestFlippedVariants(bitFlips, "amount=900");

        Console.WriteLine("\n\nTesting Grouped Byte Flips...");
        TestFlippedVariants(roleFlips, "role=admin");
    }

    static void TestFlippedVariants(List<byte[]> flippedVariants, string searchedString) {
        int index = 0;
        foreach (var mutatedMessage in flippedVariants) {
            index++;
            string? decrypted = SafeDecryptMessage(mutatedMessage, Key, IV);
            if (decrypted != null && decrypted.Contains(searchedString)) {
                Console.WriteLine($"Successful alteration found at {index}.");
                Console.WriteLine($"Decrypted message after attack: \"{decrypted}\"\n");
            }
        }
    }

    static List<byte[]> GetBitFlippedVariants(byte[] original) {
        List<byte[]> variants = [];
        for (int i = 0; i < original.Length * 8; i++) {
            byte[] mutated = (byte[])original.Clone();
            int byteIndex = i / 8;
            int bitIndex = i % 8;
            mutated[byteIndex] ^= (byte)(1 << bitIndex);
            variants.Add(mutated);
        }
        return variants;
    }

    static List<byte[]> GetRoleFlippedVariants(byte[] original) {
        List<byte[]> variants = [];
        byte[] guestBytes = Encoding.UTF8.GetBytes("guest");
        byte[] adminBytes = Encoding.UTF8.GetBytes("admin");
        int groupSize = 5;

        byte[] xorKey = new byte[guestBytes.Length];
        for (int i = 0; i < guestBytes.Length; i++) {
            xorKey[i] = (byte)(guestBytes[i] ^ adminBytes[i]); // guest XOR admin -- for inversion of roles
        }

        for (int i = 0; i <= original.Length - groupSize; i++) {
            byte[] mutated = (byte[])original.Clone();
            for (int j = 0; j < groupSize; j++) {
                mutated[i + j] ^= xorKey[j];
            }
            variants.Add(mutated);
        }
        return variants;
    }

    static string? SafeDecryptMessage(byte[] cipherText, byte[] key, byte[] iv) {
        try {
            return DecryptMessage(cipherText, key, iv);
        } catch (CryptographicException) {
            return null;
        }
    }

    static string DecryptMessage(byte[] cipherText, byte[] key, byte[] iv) {
        using Aes aesAlg = Aes.Create();
        aesAlg.Key = key;
        aesAlg.IV = iv;
        aesAlg.Mode = CipherMode.CBC;
        aesAlg.Padding = PaddingMode.PKCS7;

        using ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
        return Encoding.UTF8.GetString(PerformCryptography(cipherText, decryptor));
    }

    static byte[] EncryptMessage(string message, byte[] key, byte[] iv) {
        using Aes aesAlg = Aes.Create();
        aesAlg.Key = key;
        aesAlg.IV = iv;
        aesAlg.Mode = CipherMode.CBC;
        aesAlg.Padding = PaddingMode.PKCS7;

        using ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
        return PerformCryptography(Encoding.UTF8.GetBytes(message), encryptor);
    }

    static byte[] PerformCryptography(byte[] data, ICryptoTransform cryptoTransform) {
        using var ms = new System.IO.MemoryStream();
        using (var cs = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write)) {
            cs.Write(data, 0, data.Length);
            cs.FlushFinalBlock();
        }
        return ms.ToArray();
    }

    static void PrintByteArray(byte[] byteArray) {
        Console.WriteLine(BitConverter.ToString(byteArray).Replace("-", " "));
    }

    static byte[] ConvertHexStringToByteArray(string hex) {
        return [.. Enumerable.Range(0, hex.Length)
                         .Where(x => x % 2 == 0)
                         .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))];
    }
}
