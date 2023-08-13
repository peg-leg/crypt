//A simple Windows .Net 6 console app to encrypt a string using a static key (password)
//Thanks to Vivek Kumar for code samples adapted below
//https://www.c-sharpcorner.com/article/encryption-and-decryption-using-a-symmetric-key-in-c-sharp/
//https://vivekkumar.com

using System.Security.Cryptography;
using System.Text;

try
{
    Console.WriteLine("String encryption / decryption using a symmetric key.\nUsage: crypt       - (no parameters) will allow you to decrypt a base64 encoded encrypted string.\n       crypt e     - allows you to encrypt any string to a base64 encoded encrypted string.");
    bool result = args.Equals("e");
    if (!result && args.Length > 0)
    {
        Console.WriteLine("Invalid parameter, please see instructions above.");
    }

    var passwd = string.Empty;
    var passwd2 = string.Empty;
    int tries = 0;
    do
    {
        if (tries > 0) { Console.WriteLine("\nPasswords don't match"); }
        tries = 1;
        passwd = string.Empty;
        Console.WriteLine("\nPlease enter a password.");
        ConsoleKey key;
        do
        {
            var keyInfo = Console.ReadKey(intercept: true);
            key = keyInfo.Key;

            if (key == ConsoleKey.Backspace && passwd.Length > 0)
            {
                Console.Write("\b \b");
                passwd = passwd[0..^1];
            }
            else if (!char.IsControl(keyInfo.KeyChar))
            {
                Console.Write("*");
                passwd += keyInfo.KeyChar;
            }

        } while (key != ConsoleKey.Enter);

        if ((args.Length) > 0)
        {
            passwd2 = string.Empty;
            Console.WriteLine("\nPlease re-enter the password.");
            do
            {
                var keyInfo = Console.ReadKey(intercept: true);
                key = keyInfo.Key;

                if (key == ConsoleKey.Backspace && passwd2.Length > 0)
                {
                    Console.Write("\b \b");
                    passwd2 = passwd2[0..^1];
                }
                else if (!char.IsControl(keyInfo.KeyChar))
                {
                    Console.Write("*");
                    passwd2 += keyInfo.KeyChar;
                }

            } while (key != ConsoleKey.Enter);
        } else
        {
            passwd2 = passwd;
        }
    } while (passwd != passwd2);

    passwd = passwd.PadLeft(32, 'a');
    var str = string.Empty;
    if ((args.Length) > 0)
    {
        Console.WriteLine("\nPlease enter the string for encryption");
        str = Console.ReadLine();
        var encryptedString = AesOperation.EncryptString(passwd, str);
        Console.WriteLine($"encrypted string = {encryptedString}");
    }
    else
    {
        Console.WriteLine("\nPlease enter the string for decryption");
        str = Console.ReadLine();
        var decryptedString = AesOperation.DecryptString(passwd, str);
        Console.WriteLine($"decrypted string = {decryptedString}");
    }
    Console.ReadKey();
}
catch (Exception e)
{
    Console.WriteLine("An error occurred, please check the password and entered string.");
    //Console.WriteLine(e.Message);
    Console.ReadKey();
}

public class AesOperation
{
    public static string EncryptString(string passwd, string plainText)
    {
        byte[] iv = new byte[16];
        byte[] array;

        using (Aes aes = Aes.Create())
        {
            aes.Key = Encoding.UTF8.GetBytes(passwd);
            aes.IV = iv;

            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter streamWriter = new StreamWriter((Stream)cryptoStream))
                    {
                        streamWriter.Write(plainText);
                    }

                    array = memoryStream.ToArray();
                }
            }
        }

        return Convert.ToBase64String(array);
    }

    public static string DecryptString(string passwd, string cipherText)
    {
        byte[] iv = new byte[16];
        byte[] buffer = Convert.FromBase64String(cipherText);
        using (Aes aes = Aes.Create())
        {
            aes.Key = Encoding.UTF8.GetBytes(passwd);
            aes.IV = iv;
            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            using (MemoryStream memoryStream = new MemoryStream(buffer))
            {
                using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader streamReader = new StreamReader((Stream)cryptoStream))
                    {
                        return streamReader.ReadToEnd();
                    }
                }
            }
        }
    }
}
