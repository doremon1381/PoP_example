using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace PoP_example
{
    public static class RSAEncryptUtilities
    {
        public static (RSAParameters PublicKey,RSAParameters PrivateKey) GeneratePrivateAndPublicKey()
        {
            RSAParameters publicKey;
            RSAParameters privateKey;

            if (KeyCanBeUsed())
            {
                publicKey = GetJsonKey();
                privateKey = GetJsonKey(false);
            }
            else
            {
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    publicKey = rsa.ExportParameters(false);
                    privateKey = rsa.ExportParameters(true);
                }

                ExportKey(publicKey);
                ExportKey(privateKey, false);
            }

            return (publicKey, privateKey);
        }

        private static RSAParameters GetJsonKey(bool isPublicKey = true)
        {
            var keyFile = new FileInfo(GetFilePath(isPublicKey));
            RSAParameters key = default;

            if (keyFile.Exists)
            {
                string str = "";
                using (var stream = keyFile.OpenText())
                {
                    str = stream.ReadToEnd();
                }

                key = JsonConvert.DeserializeObject<RSAParameters>(str);
            }
            else
                throw new Exception("Key is null!");

            return key;
        }

        private static void ExportKey(RSAParameters key, bool isPublicKey = true)
        {
            // create file info
            // open or create using stream
            // serialize key as json
            // get byte array of json file
            // write byte[] to stream, close it
            FileInfo keyFile = new FileInfo(GetFilePath(isPublicKey));

            using (FileStream fs = new FileStream(GetFilePath(isPublicKey), FileMode.OpenOrCreate))
            {
                var json = JsonConvert.SerializeObject(key);
                byte[] bytes = Encoding.UTF8.GetBytes(json);

                fs.Write(bytes, 0, bytes.Length);
            }
        }

        private static bool KeyCanBeUsed(bool isPublicKey = true)
        {
            FileInfo key = new FileInfo(GetFilePath(isPublicKey));

            if (key.Exists)
            {
                return true;
            }
            return false;
        }

        private static string GetFilePath(bool isPublicKey = true)
        {
            return isPublicKey switch
            {
                true => $"{Environment.CurrentDirectory}\\Keys\\Rsa_publicKey.json",
                false => $"{Environment.CurrentDirectory}\\Keys\\Rsa_privateKey.json",
            };
        }
    }
}
