using System.Text;

//implementation of the IV reuse attack
//the main point is to xor the bytes in order to analyse the patterns (next step could be matching the symbols while comparing them to the IV (if it is not secret))
namespace Cryptography_AES
{
    public class iv_reuse
    {
            public void IVReuse()
            {
                byte[] key = Encoding.UTF8.GetBytes("qwerty1010123456");
                byte[] iv = Encoding.UTF8.GetBytes("asdfghjklzxcvbnm");

                AES_CBC aesCbc = new(key, iv);

                byte[] plaintext1 = Encoding.UTF8.GetBytes("This is a message!");
                byte[] plaintext2 = Encoding.UTF8.GetBytes("This is a secret message.");
                byte[] plaintext3 = Encoding.UTF8.GetBytes("This is a new message?");

                byte[] ciphertext1 = aesCbc.Encrypt(plaintext1);
                byte[] ciphertext2 = aesCbc.Encrypt(plaintext2);
                byte[] ciphertext3 = aesCbc.Encrypt(plaintext3);

                Console.WriteLine("Ciphertext 1: " + BitConverter.ToString(ciphertext1));
                Console.WriteLine("Ciphertext 2: " + BitConverter.ToString(ciphertext2));
                Console.WriteLine("Ciphertext 3: " + BitConverter.ToString(ciphertext3));

                byte[] xor1 = new byte[ciphertext1.Length];
                byte[] xor2 = new byte[ciphertext1.Length];

                for (int i = 0; i < ciphertext1.Length; i++) // XOR of the two first ciphertexts
                {
                    xor1[i] = (byte)(ciphertext1[i] ^ ciphertext2[i]);
                }

                for (int i = 0; i < ciphertext1.Length; i++) // XOR of xor1 and ciphertext3
                {
                    xor2[i] = (byte)(ciphertext1[i] ^ xor1[i]);
                }

                Console.WriteLine("XOR of Ciphertext 1 and 2: " + BitConverter.ToString(xor1));
                Console.WriteLine("XOR of xor1 and Ciphertext 3: " + BitConverter.ToString(xor2));

                PerformStatisticalAnalysis(xor1);
                PerformStatisticalAnalysis(xor2);
            }

            private void PerformStatisticalAnalysis(byte[] xorResult) // frequency analysis
            {
                Dictionary<byte, int> byteFrequency = new Dictionary<byte, int>();

                foreach (byte b in xorResult)
                {
                    if (byteFrequency.ContainsKey(b))
                    {
                        byteFrequency[b]++;
                    }
                    else
                    {
                        byteFrequency[b] = 1;
                    }
                }

                Console.WriteLine("\nStatistical Analysis (Byte Frequency):");

                int maxFrequency = byteFrequency.Values.Max();

                var mostFrequentBytes = byteFrequency.Where(kvp => kvp.Value == maxFrequency).ToList();

                foreach (var kvp in mostFrequentBytes)
                {
                    Console.WriteLine($"Byte: 0x{kvp.Key:X2}, Frequency: {kvp.Value}");
                }
            }

            public static void Main(string[] args)
            {
                iv_reuse iv = new iv_reuse();
                iv.IVReuse();
            }
    }
}
