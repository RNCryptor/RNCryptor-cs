using System;
using System.Text;
using RNCryptor;

namespace rncrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            var password = "password";
            var plaintext = "attack at dawn";
            var encryptor = new Encryptor();
            var encrypted = encryptor.Encrypt(Encoding.Default.GetBytes(plaintext), password);

            var decryptor = new Decryptor();
            var decrypted = decryptor.Decrypt(encrypted, password);

            var decryptedString = Encoding.Default.GetString(decrypted);
            Console.WriteLine(decryptedString);
        }
    }
}
