using System;
using System.Text;


//the logic is to decrypt the ciphertexts using the oracle and then XOR the decrypted text with the IV to get the plaintext
//the IV is known and the key is randomly generated
//(the plain texts are not fully found but the logic is implemented)

namespace Cryptography_AES
{
    public class AES_CBC_Oracle
    {
        private readonly byte[] key;
        private readonly byte[] iv;
        private readonly AES_CBC aesCbc;

        // oracle gets IV and randomly generates a key
        public AES_CBC_Oracle(byte[] iv)
        {
            this.iv = iv;
            this.key = RandKeyGen.GenerateKey(128);
            aesCbc = new AES_CBC(this.key, iv);
        }

        // decrypts only with the oracle (one block to get the one with IV)
        public byte[] OracleDecrypt(byte[] ciphertext)
        {
            return aesCbc.DecryptSingleBlock(ciphertext);
        }

        public byte[] Encrypt(byte[] plaintext)
        {
            return aesCbc.Encrypt(plaintext);
        }
    }

    public class IVReuseAttack
    {
        private static byte[] IV = Encoding.UTF8.GetBytes("asdfghjklzxcvbnm");

        public void Attack()
        {
            //3 encrypted messages
            byte[] ciphertext1 = ConvertHexStringToByteArray("E9A711C7521C50139AD84A81F05D9E06");
            byte[] ciphertext2 = ConvertHexStringToByteArray("39810F5481062AC8544124F1D54EE7CC");
            byte[] ciphertext3 = ConvertHexStringToByteArray("7D625EC450EC93418FABF36A859F3956");

            AES_CBC_Oracle oracle = new AES_CBC_Oracle(IV);

            Console.WriteLine("Recovering Plaintext:");
            RecoverPlaintext(oracle, ciphertext1);
            RecoverPlaintext(oracle, ciphertext2);
            RecoverPlaintext(oracle, ciphertext3);
        }

        private void RecoverPlaintext(AES_CBC_Oracle oracle, byte[] ciphertextBlock)
        {
            // decrypt texts
            byte[] decryptedBlock = oracle.OracleDecrypt(ciphertextBlock);

            // XOR with IV to get plain text
            byte[] plaintext = new byte[decryptedBlock.Length];
            for (int i = 0; i < decryptedBlock.Length; i++)
            {
                plaintext[i] = (byte)(decryptedBlock[i] ^ IV[i]);
            }

            // convert texts to string to make them readable
            string decodedPlaintext;
            try
            {
                decodedPlaintext = Encoding.UTF8.GetString(plaintext).Trim();
            }
            catch
            {
                decodedPlaintext = BitConverter.ToString(plaintext);
            }
            Console.WriteLine($"Recovered: {decodedPlaintext}");
        }

        //method to convert hex string to byte array (for ciphertexts)
        private byte[] ConvertHexStringToByteArray(string hex)
        {
            int length = hex.Length;
            byte[] bytes = new byte[length / 2];
            for (int i = 0; i < length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }

        public static void Main(string[] args)
        {
            IVReuseAttack attack = new IVReuseAttack();
            attack.Attack();
        }
    }
}
