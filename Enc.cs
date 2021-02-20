using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main(string[] args)
    {
        string pass = "pass";
        if(args.Length < 2)
        {
            Console.WriteLine("Usage: -enc/dec <string> -pass <string :default 'pass'>");
            return;
        }

        if(args.Length > 3)
            pass = args[3];
        Console.WriteLine("\tPass: " + pass);

        if(args[0] == "-enc")
        {
            byte[] buffer = Encoding.UTF8.GetBytes(args[1]);
            Console.WriteLine(Convert.ToBase64String(AES_Encrypt(buffer, pass)));
        }
        else if(args[0] == "-dec")
        {
            byte[] buffer = Convert.FromBase64String(args[1]);
            Console.WriteLine(Encoding.UTF8.GetString(AES_Decrypt(buffer, pass)));
        }
        else Console.WriteLine("Usage: -enc/dec <string> -pass <string : default 'pass'>"); 
    }

    public static byte[] AES_Encrypt(byte[] bytes, string AesKey)
        {
            byte[] encryptedBytes = null;
            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                    var passwordBytes = Encoding.UTF8.GetBytes(AesKey);
                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);
                    AES.Mode = CipherMode.CBC;
                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytes, 0, bytes.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }
            return encryptedBytes;
        }
        public static byte[] AES_Decrypt(byte[] bytesToBeDecrypted, string AesKey)
        {
            byte[] decryptedBytes = null;
            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                    var passwordBytes = Encoding.UTF8.GetBytes(AesKey);
                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);
                    AES.Mode = CipherMode.CBC;
                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cs.Close();
                    }
                    decryptedBytes = ms.ToArray();
                }
            }
            return decryptedBytes;
        }

}
