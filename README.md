# crypt
A simple Windows .Net 6 console app to encrypt or decrypt a string using a static key (password)

The code was tested and compiled in Visual Studio community edition 2022. Create a new .Net 6 C# console application and copy / paste the contents of the Program.cs file into your new project's program.cs file. The app assumes decode when run without parameters and encode when run with any parameter. I use it to encode sensitive text being sent across insecure channels. This is a basic quick and dirty encode / decode using symmetric AES256 without certificates so caveat emptor when using it for your sensitive data. There are no restrictions on the password complexity. Passwords are automatically padded and base64 encoded. Typically you would share the app with the person you send the data to and you should obviously share the password with them over a different channel to the one used to share the sensitive info (e.g. email and IM).

Thanks to Vivek Kumar for code samples adapted from his blog post here: https://www.c-sharpcorner.com/article/encryption-and-decryption-using-a-symmetric-key-in-c-sharp
