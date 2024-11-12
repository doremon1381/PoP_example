using System.Net.Security;
using System.Net.Sockets;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PoP_example
{
    internal class Program
    {
        static void Main(string[] args)
        {
            try
            {

                //Console.WriteLine("Hello, World!");
                var server = Task.Factory.StartNew(() => new Server());
                var client = Task.Factory.StartNew(() => new Client()).GetAwaiter().GetResult();

                for (int i = 0; i < 1; i++)
                {
                    Task.Factory.StartNew(() =>
                    {
                        client.SendMessage();
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

            Console.ReadLine();
        }
    }

    public class Client
    {
        // TODO: 1. create RSA private key 
        //     : 2. call to server to get handshake and public key
        //     : 3. random generate a pre-master secret
        //     :    encrypt the secret with private key
        //     :    send to server.
        //     : 4. 

        private RSAParameters _privateKey;

        public Client()
        {
            _privateKey = RSAEncryptUtilities.GeneratePrivateAndPublicKey().PrivateKey;
        }

        public void SendMessage()
        {
            var client = new TcpClient("localhost", 443);
            var sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
            sslStream.AuthenticateAsClient("localhost");

            var message = Encoding.UTF8.GetBytes("Hello from TLS Client");
            sslStream.Write(message);
            sslStream.Flush();

            var buffer = new byte[2048];

            int bytesRead = sslStream.Read(buffer, 0, buffer.Length);
            var response = Encoding.UTF8.GetString(buffer, 0, bytesRead);

            Console.WriteLine("Received: " + response);
            client.Close();
        }

        public static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            //return true; // For testing purposes, always accept the server certificate

            if (sslPolicyErrors == SslPolicyErrors.None)
            {
                return true; // No errors, certificate is valid 
            }

            Console.WriteLine("Certificate error: {0}", sslPolicyErrors);
            // Check if the certificate is expired
            if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0)
            {
                Console.WriteLine("Certificate not available.");
                return false;
            }
            // Check if the certificate chain is valid
            if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateChainErrors) != 0)
            {
                foreach (X509ChainStatus status in chain.ChainStatus)
                {
                    if (status.Status == X509ChainStatusFlags.UntrustedRoot)
                    {
                        // TODO: ignore for now
                        return true;
                    }
                    else if (status.Status != X509ChainStatusFlags.NoError)
                    {
                        Console.WriteLine("Chain error: {0}", status.StatusInformation);
                        return false;
                    }
                }
            }
            // Check if the certificate name matches the server's hostname
            if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
            {
                Console.WriteLine("Certificate name mismatch.");
                return false;
            }

            // If you want to accept the certificate despite the errors, return true 
            // For production, you should handle each error appropriately return
            return false;
        }
    }

    public class Server
    {
        public Server()
        {
            var certificate = new X509Certificate2($"{Environment.CurrentDirectory}\\Certificate\\certificate_new.pfx", "5je486MgXr7lnKnHLLzRT!FEfFc5");
            var listener = new TcpListener(IPAddress.Any, 443);
            listener.Start();
            Console.WriteLine("TLS Server started...");

            while (true)
            {
                var client = listener.AcceptTcpClient();

                // after catch request from client
                var sslStream = new SslStream(client.GetStream(), false);
                sslStream.AuthenticateAsServer(certificate, false, System.Security.Authentication.SslProtocols.Tls12, true);
                var buffer = new byte[2048];
                int bytesRead = sslStream.Read(buffer, 0, buffer.Length);

                var message = Encoding.UTF8.GetString(buffer, 0, bytesRead);

                Console.WriteLine("Received: " + message);

                var response = Encoding.UTF8.GetBytes("Hello from TLS Server");
                sslStream.Write(response);
                sslStream.Flush();
                client.Close();
            }
        }
    }
}
