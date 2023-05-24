using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Security.Cryptography;
using System.IO;

namespace Secure_Channel_Server
{
    public partial class Form1 : Form
    {
        private bool terminating = false;
        private bool listening = false;

        private Socket serverSocket;
        private List<Socket> socketList = new List<Socket>();

        // this will help to keep track of online and connected users to server to avoid any duplicate usernamed users
        private List<string> active_users = new List<string>();

        private string RSAxmlKey3072_enc_dec;
        private string RSAxmlKey3072_sign_verif;

        private byte[] mathKey;
        private byte[] mathIV;
        private byte[] mathHMACkey;

        private byte[] ifKey;
        private byte[] ifIV;
        private byte[] ifHMACkey;

        private byte[] spsKey;
        private byte[] spsIV;
        private byte[] spsHMACkey;

        private string db = "../../db.txt";

        private string serverIp;

        public Form1()
        {
            using (System.IO.StreamReader fileReader =
            new System.IO.StreamReader("../../server_enc_dec_pub_prv.txt"))
            {
                RSAxmlKey3072_enc_dec = fileReader.ReadLine();
            }

            using (System.IO.StreamReader fileReader =
            new System.IO.StreamReader("../../server_sign_verify_pub_prv.txt"))
            {
                RSAxmlKey3072_sign_verif = fileReader.ReadLine();
            }

            String hostname = Dns.GetHostName();
            IPAddress[] ipAddresses = Dns.GetHostAddresses(hostname);

            createDB();

            foreach (IPAddress ipAddress in ipAddresses)
            {
                if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    serverIp = ipAddress.ToString();
                    break;
                }
            }

            Control.CheckForIllegalCrossThreadCalls = false;
            this.FormClosing += new FormClosingEventHandler(Form1_FormClosing);
            InitializeComponent();
        }

        private void btnStart_Click(object sender, EventArgs e)
        {
            terminating = false;
            int serverPort;
            Thread acceptThread;

            if (Int32.TryParse(txtPort.Text, out serverPort))
            {
                mathKeyGenBtn.Enabled = true;
                ifKeyGenBtn.Enabled = true;
                spsKeyGenBtn.Enabled = true;
                btnStop.Enabled = true;

                serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

                serverSocket.Bind(new IPEndPoint(IPAddress.Any, serverPort));
                serverSocket.Listen(3);

                listening = true;
                btnStart.Enabled = false;
                txtPort.ReadOnly = true;
                txtPort.Enabled = false;
                acceptThread = new Thread(new ThreadStart(Accept));
                acceptThread.Start();

                
                AddMessage("Server started");
                AddMessage("Listening on " + serverIp + ":" + serverPort);

                AddMessage("\r\n\r\n" + "hex(RSA Encryption key): " + generateHexStringFromString(RSAxmlKey3072_enc_dec));
                AddMessage("\r\n\r\n" + "hex(RSA Sign key): " + generateHexStringFromString(RSAxmlKey3072_sign_verif));
            }
            else
            {
                AddMessage("Please check port number!");
            }
        }

        private void btnStop_Click(object sender, EventArgs e)
        {
            listening = false;
            terminating = true;
            AddMessage("");
            if (socketList.Count > 0)
            {
                AddMessage("Following disconnected due to termination!");
                for (int i = 0; i < socketList.Count; i++)
                {
                    AddMessage(" - " + getClientIp(socketList[i].RemoteEndPoint));
                    socketList[i].Close();
                }
            }
            serverSocket.Close();
            socketList.Clear();
            AddMessage("Server has stopped!");
            AddMessage("-------------------");
            btnStop.Enabled = false;
            btnStart.Enabled = true;
            txtPort.ReadOnly = false;
            txtPort.Enabled = true;

            mathKey = new byte[0];
            mathIV = new byte[0];
            mathHMACkey = new byte[0];
            mathSecretKey.Enabled = true;
            mathSecretKey.Clear();

            ifKey = new byte[0];
            ifIV = new byte[0];
            ifHMACkey = new byte[0];
            ifSecretKey.Enabled = true;
            ifSecretKey.Clear();

            spsKey = new byte[0];
            spsIV = new byte[0];
            spsHMACkey = new byte[0];
            spsSecretKey.Enabled = true;
            spsSecretKey.Clear();

            txtPort.Clear();
        }

        private void Accept()
        {
            while (listening)
            {
                try
                {
                    Socket clientSocket = serverSocket.Accept();
                    socketList.Add(clientSocket);
                    AddMessage(getClientIp(clientSocket.RemoteEndPoint) + " connected!");

                    Thread receiveThread = new Thread(new ThreadStart(Receive));
                    receiveThread.Start();
                }
                catch
                {
                    if (terminating)
                    {
                        listening = false;
                    }
                    else
                    {
                        AddMessage("The socket stopped working!");
                    }
                }
            }
        }

        private void mathKeyGenBtn_Click(object sender, EventArgs e)
        {
            string secretKey = mathSecretKey.Text;

            if (secretKey == "")
            {
                AddMessage("\r\n\r\n" + "The secret key for MATH101 channel cannot be empty!");
                return;
            }

            byte[] hashedKey = hashWithSHA512(secretKey);
            string hexKey = generateHexStringFromByteArray(hashedKey);
            mathKey = hexStringToByteArray(hexKey.Substring(0, 32));
            mathIV = hexStringToByteArray(hexKey.Substring(32, 32));
            mathHMACkey = hexStringToByteArray(hexKey.Substring(64, 32));

            AddMessage("\r\n\r\n" + "The AES128 Key for MATH101 channel: " + hexKey.Substring(0, 32));
            AddMessage("\r\n" + "The AES128 IV for MATH101 channel: " + hexKey.Substring(32, 32));
            AddMessage("\r\n" + "The HMAC Key for MATH101 channel: " + hexKey.Substring(64, 32));

            mathKeyGenBtn.Enabled = false;
            mathSecretKey.Enabled = false;

        }

        private void spsKeyGenBtn_Click(object sender, EventArgs e)
        {
            string secretKey = spsSecretKey.Text;

            if (secretKey == "")
            {
                AddMessage("\r\n\r\n" + "The secret key for SPS101 channel cannot be empty!");
                return;
            }

            byte[] hashedKey = hashWithSHA512(secretKey);
            string hexKey = generateHexStringFromByteArray(hashedKey);
            spsKey = hexStringToByteArray(hexKey.Substring(0, 32));
            spsIV = hexStringToByteArray(hexKey.Substring(32, 32));
            spsHMACkey = hexStringToByteArray(hexKey.Substring(64, 32));

            AddMessage("\r\n\r\n" + "The AES128 Key for SPS101 channel: " + hexKey.Substring(0, 32));
            AddMessage("\r\n" + "The AES128 IV for SPS101 channel: " + hexKey.Substring(32, 32));
            AddMessage("\r\n" + "The HMAC Key for SPS101 channel: " + hexKey.Substring(64, 32));

            spsKeyGenBtn.Enabled = false;
            spsSecretKey.Enabled = false;
        }

        private void ifKeyGenBtn_Click(object sender, EventArgs e)
        {
            string secretKey = ifSecretKey.Text;

            if (secretKey == "")
            {
                AddMessage("\r\n\r\n" + "The secret key for IF100 channel cannot be empty!");
                return;
            }

            byte[] hashedKey = hashWithSHA512(secretKey);
            string hexKey = generateHexStringFromByteArray(hashedKey);
            ifKey = hexStringToByteArray(hexKey.Substring(0, 32));
            ifIV = hexStringToByteArray(hexKey.Substring(32, 32));
            ifHMACkey = hexStringToByteArray(hexKey.Substring(64, 32));

            AddMessage("\r\n\r\n" + "The AES128 Key for IF100 channel: " + hexKey.Substring(0, 32));
            AddMessage("\r\n" + "The AES128 IV for IF100 channel: " + hexKey.Substring(32, 32));
            AddMessage("\r\n" + "The HMAC Key for IF100 channel: " + hexKey.Substring(64, 32));

            ifKeyGenBtn.Enabled = false;
            ifSecretKey.Enabled = false;
            
        }

        private void broadcastMessage(byte[] message, string channel)
        {
            for (int x = 0; x < active_users.Count(); x++)
            {
                if (getChannel(active_users[x]) == channel)
                {
                    socketList[x].Send(message);
                }
            }
        }

        private void Receive()
        {
            Socket s = socketList[socketList.Count - 1];
            bool connected = true;
            bool loggedIn = false;
            string subscribedChannel = "";
            string user = "";

            while (connected && !terminating)
            {
                try
                {
                    if (loggedIn)
                    {
                        while (loggedIn && connected && !terminating)
                        {
                            Byte[] buffer = new Byte[3072];
                            s.Receive(buffer);
                            // Bir mesaj geldi, doğru channel'ı bul oraya logu gir. Broadcast fonkunu çağır bütün online clientlera mesajı olduğu gibi gönder.

                            AddMessage("\r\n\r\n" + "A message came from " + user + " to channel " + subscribedChannel + " and it is broadcasted to all online clients in that channel.");

                            if (subscribedChannel == "IF100") ifChannel.AppendText("\r\n\r\n" + "Incoming message from " + user + ": " + Encoding.ASCII.GetString(buffer));
                            else if (subscribedChannel == "SPS101") spsChannel.AppendText("\r\n\r\n" + "Incoming message from " + user + ": " + Encoding.ASCII.GetString(buffer));
                            else if (subscribedChannel == "MATH101") mathChannel.AppendText("\r\n\r\n" + "Incoming message from " +user +": " + Encoding.ASCII.GetString(buffer));

                            broadcastMessage(buffer, subscribedChannel);
                        }
                        
                    }
                    else
                    {
                        Byte[] buffer = new Byte[3072];
                        s.Receive(buffer);

                        string incomingMessageHexS = Encoding.Default.GetString(buffer);
                        incomingMessageHexS = incomingMessageHexS.Substring(0, incomingMessageHexS.IndexOf("\0"));

                        // if it has "auth:" at beggining of string then it is a login request
                        if (incomingMessageHexS.Substring(0, 5) == "auth:")
                        {
                            // Login Phase

                            user = incomingMessageHexS.Substring(5);
                            string pass = getPass(user);

                   

                            AddMessage("\r\n\r\n" + "A login request come from ip " + getClientIp(s.RemoteEndPoint) + " , and username "  + user + ". The message is: " + incomingMessageHexS);

                            

                            // Generating 128-bit random number using Cryptography library
                            byte[] randomNumber = new byte[16];
                            using (var rng = new RNGCryptoServiceProvider())
                            {
                                rng.GetBytes(randomNumber);
                            }
                            string rndNum = Encoding.Default.GetString(randomNumber);
                            AddMessage("\r\n\r\n" + "Created and sent 128 bit number for challenge: " + generateHexStringFromByteArray(randomNumber));
                            s.Send(randomNumber);

                            Byte[] client_HMACrnd = new Byte[64];
                            s.Receive(client_HMACrnd);

                            AddMessage("\r\n\r\n" + "HMAC of the number received from the client: " + generateHexStringFromByteArray(client_HMACrnd));

                            string response;

                            /*  if pass="" it means that there is no such user in 
                             *  db, so since there is no a user to use its password
                             *  as encryption key of authentication request response
                             *  then no_user response will be sent in clear
                            */
                            if (pass == "")
                            {
                                response = "no_user";

                                AddMessage("\r\n\r\n" + getClientIp(s.RemoteEndPoint) + " There is no enrolled user with name " + user +"! So that HMAC verification skipped, and response sent!");
                            }
                            else if ((getChannel(user) == "IF100" && ifKey == null) || (getChannel(user) == "SPS101" && spsKey == null) || (getChannel(user) == "MATH101" && mathKey == null))
                            {
                                response = "not_available";
                                AddMessage("\r\n\r\n" + getClientIp(s.RemoteEndPoint) + " The "+ getChannel(user) + " channel is currently not available. " + user + " cannot join the channel.");
                            }
                            else
                            {
                                // lower quarter of string means first 25% of string
                                byte[] lowerQuarter = hexStringToByteArray(pass.Substring(0, 32));
                                byte[] HMACrnd = applyHMACwithSHA512(rndNum, lowerQuarter);

                                if (HMACrnd.SequenceEqual(client_HMACrnd))
                                {
                                    AddMessage("\r\n\r\n" + "HMAC verified.");
                                    if (active_users.Contains(user))
                                    {
                                        response = "already";

                                        AddMessage("\r\n\r\n" + getClientIp(s.RemoteEndPoint) + " There is already a user online with the username " + user + "!");
                                    }
                                    else
                                    {
                                        response = "success:";

                                        string channel = getChannel(user);

                                        if (channel == "MATH101")
                                        {
                                            string channelKeys = generateHexStringFromByteArray(mathKey) + ":" + generateHexStringFromByteArray(mathIV) + ":" + generateHexStringFromByteArray(mathHMACkey) + ":" + "MATH101";
                                            response += channelKeys;
                                        }
                                        else if (channel == "SPS101")
                                        {
                                            string channelKeys = generateHexStringFromByteArray(spsKey) + ":" + generateHexStringFromByteArray(spsIV) + ":" + generateHexStringFromByteArray(spsHMACkey) + ":" + "SPS101";
                                            response += channelKeys;
                                        }
                                        else if (channel == "IF100")
                                        {
                                            string channelKeys = generateHexStringFromByteArray(ifKey) + ":" + generateHexStringFromByteArray(ifIV) + ":" + generateHexStringFromByteArray(ifHMACkey) + ":" + "IF100" ;
                                            response += channelKeys;
                                        }
                                        else
                                        {
                                            AddMessage("The channel name could not recognized!");
                                        }
                                        

                                        AddMessage("\r\n\r\n" + getClientIp(s.RemoteEndPoint) +"  " + user +" is successfully authenticated!");

                                        AddMessage("\r\n\r\n" + "Plaintext response message is: " + response);

                                        active_users.Add(user);
                                        loggedIn = true;
                                        subscribedChannel = getChannel(user);
                                    }
                                }
                                else
                                {
                                    response = "error";

                                    AddMessage("\r\n\r\n" + getClientIp(s.RemoteEndPoint) +"  " +user +" failed to log in due to wrong password!");
                                }

                                byte[] AES128key = hexStringToByteArray(pass.Substring(64, 32));
                                byte[] AES128IV = hexStringToByteArray(pass.Substring(96, 32));

                                AddMessage("\r\n\r\n" + "AES-128 key is: " + generateHexStringFromByteArray(AES128key));
                                AddMessage("\r\n\r\n" + "AES-128 IV is: " + generateHexStringFromByteArray(AES128IV));

                                byte[] auth_res = encryptWithAES128(response, AES128key, AES128IV);
                                response = generateHexStringFromByteArray(auth_res);
                                AddMessage("\r\n\r\n" + "Encrypted response message is: " + response);
                            }

                            byte[] auth_res_signed = signWithRSA(response, 3072, RSAxmlKey3072_sign_verif);
                            string signedResponseHexS = generateHexStringFromByteArray(auth_res_signed) + '\0';

                            AddMessage("\r\n\r\n" + "Signed response message is: " + signedResponseHexS);

                            // concatinating response message with its signiture
                            string auth_sign_res = response + ":auth:" + signedResponseHexS;
                            byte[] signedResponseHex = Encoding.ASCII.GetBytes(auth_sign_res);

                            s.Send(signedResponseHex);

                            if(!loggedIn)
                            {
                                AddMessage("\r\n\r\n" + getClientIp(s.RemoteEndPoint) + " disconnected!");

                                s.Close();
                                socketList.Remove(s);
                                connected = false;
                            }
                        }
                        else
                        {
                            // Enroll Phase;
                            byte[] incomingMessageHex = hexStringToByteArray(incomingMessageHexS);
                            string incomingMessage = Encoding.Default.GetString(incomingMessageHex);

                            AddMessage("\r\n\r\n" + "An enrollment request come from " + getClientIp(s.RemoteEndPoint) + ": " + incomingMessageHexS);


                            byte[] decrypt = decryptWithRSA(incomingMessage, 3072, RSAxmlKey3072_enc_dec);
                            string decryptS = Encoding.Default.GetString(decrypt);
                            AddMessage("\r\n\r\n" + "After decryption: " + decryptS);
                            //AddMessage(getClientIp(s.RemoteEndPoint) + " sent request with following payload: " + decryptS);

                            

                            string[] data = decryptS.Split(':');
                            string response;
                            if (userExist(data[1]))
                            {
                                response = "error";
                                AddMessage("\r\n\r\n" + "This username is taken. The message 'error' is signed and sent back to client.");
                            }
                            else
                            {
                                response = "success";
                                AddMessage("\r\n\r\n" + "The enrollment succeed the message 'success' is signed and sent back to client, and required information is written to database.");
                                write2DB(decryptS);
                            }
                            byte[] signedResponse = signWithRSA(response, 3072, RSAxmlKey3072_sign_verif);
                            string signedResponseHexS = generateHexStringFromByteArray(signedResponse) + '\0';

                            AddMessage("\r\n\r\n" + "Signed and sent message: " + signedResponseHexS);

                            byte[] signedResponseHex = Encoding.ASCII.GetBytes(signedResponseHexS);

                            s.Send(signedResponseHex);

                            
                            //AddMessage(getClientIp(s.RemoteEndPoint) + "'s enrollment response in hex format: " + generateHexStringFromByteArray(signedResponse));

                            AddMessage("\r\n\r\n" + getClientIp(s.RemoteEndPoint) + " disconnected!");

                            s.Close();
                            socketList.Remove(s);
                            connected = false;
                        }
                    }
                }
                catch 
                {
                    if (!terminating)
                    {
                        
                        AddMessage("\r\n\r\n" + getClientIp(s.RemoteEndPoint) + " A client disconnected!");

                        if (active_users.Contains(user))
                        {
                            active_users.Remove(user);
                            AddMessage(user + " is removed from online users list!");
                        }
                    }


                    s.Close();
                    socketList.Remove(s);
                    
                    
                    
                    connected = false;
                }
            }
        }

        private void createDB() 
        {
            if (!File.Exists(db))
            {
                File.WriteAllText(db, "");
            }
        }

        private bool userExist(string s) 
        {
            if (File.Exists(db))
            {
                using (StreamReader reader = new StreamReader(db))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        string[] data = line.Split(':');
                        if(data[1] == s)
                        {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        private bool correctPass(string user, string pass)
        {
            if (File.Exists(db))
            {
                using (StreamReader reader = new StreamReader(db))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        string[] data = line.Split(':');
                        if (data[1] == user)
                        {
                            return data[0] == pass;
                        }
                    }
                }
            }
            return false;
        }

        static string generateHexStringFromString(string input)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(input);
            return BitConverter.ToString(bytes).Replace("-", "");
        }

        private string getPass(string user)
        {
            if (File.Exists(db))
            {
                using (StreamReader reader = new StreamReader(db))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        string[] data = line.Split(':');
                        if (data[1] == user)
                        {
                            return data[0];
                        }
                    }
                }
            }
            return "";
        }

        private string getChannel(string user)
        {
            if (File.Exists(db))
            {
                using (StreamReader reader = new StreamReader(db))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        string[] data = line.Split(':');
                        if (data[1] == user)
                        {
                            return data[2];
                        }
                    }
                }
            }
            return "";
        }

        private void write2DB(string s) 
        {
            if(File.Exists(db))
            {
                using (StreamWriter writer = File.AppendText(db))
                {
                    writer.WriteLine(s);
                }
            }
        }

        private void AddMessage(string message)
        {
            if (txtOutput.InvokeRequired)
            {
                txtOutput.Invoke(new Action<string>(AddMessage), message);
            }
            else
            {
                txtOutput.AppendText(message + Environment.NewLine);
            }
        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            for (int i = 0; i < socketList.Count; i++)
            {
                AddMessage(" - " + getClientIp(socketList[i].RemoteEndPoint));
                socketList[i].Close();
            }
            listening = false;
            terminating = true;
            Environment.Exit(0);
        }

        private string getClientIp(EndPoint SocketEndpoint)
        {
            IPEndPoint remoteIpEndPoint = (IPEndPoint)SocketEndpoint;
            return remoteIpEndPoint.Address.ToString();
        }

        private string getClientport(EndPoint SocketEndpoint)
        {
            IPEndPoint remoteIpEndPoint = (IPEndPoint)SocketEndpoint;
            return remoteIpEndPoint.Port.ToString();
        }

        static string generateHexStringFromByteArray(byte[] input)
        {
            string hexString = BitConverter.ToString(input);
            return hexString.Replace("-", "");
        }

        public static byte[] hexStringToByteArray(string hex)
        {
            int numberChars = hex.Length;
            byte[] bytes = new byte[numberChars / 2];
            for (int i = 0; i < numberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        // RSA decryption with varying bit length
        static byte[] decryptWithRSA(string input, int algoLength, string xmlStringKey)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create RSA object from System.Security.Cryptography
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(algoLength);
            // set RSA object with xml string
            rsaObject.FromXmlString(xmlStringKey);
            byte[] result = null;

            try
            {
                result = rsaObject.Decrypt(byteInput, true);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }

        static byte[] hashWithSHA512(string input)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create a hasher object from System.Security.Cryptography
            SHA512CryptoServiceProvider sha512Hasher = new SHA512CryptoServiceProvider();
            // hash and save the resulting byte array
            byte[] result = sha512Hasher.ComputeHash(byteInput);

            return result;
        }

        // signing with RSA
        static byte[] signWithRSA(string input, int algoLength, string xmlString)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create RSA object from System.Security.Cryptography
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(algoLength);
            // set RSA object with xml string
            rsaObject.FromXmlString(xmlString);
            byte[] result = null;

            try
            {
                result = rsaObject.SignData(byteInput, "SHA512");
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }

        // HMAC with SHA-512
        static byte[] applyHMACwithSHA512(string input, byte[] key)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create HMAC applier object from System.Security.Cryptography
            HMACSHA512 hmacSHA512 = new HMACSHA512(key);
            // get the result of HMAC operation
            byte[] result = hmacSHA512.ComputeHash(byteInput);

            return result;
        }

        // encryption with AES-128
        static byte[] encryptWithAES128(string input, byte[] key, byte[] IV)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);

            // create AES object from System.Security.Cryptography
            RijndaelManaged aesObject = new RijndaelManaged();
            // since we want to use AES-128
            aesObject.KeySize = 128;
            // block size of AES is 128 bits
            aesObject.BlockSize = 128;
            // mode -> CipherMode.*
            aesObject.Mode = CipherMode.CBC;
            // feedback size should be equal to block size
            aesObject.FeedbackSize = 128;
            // set the key
            aesObject.Key = key;
            // set the IV
            aesObject.IV = IV;
            // create an encryptor with the settings provided
            ICryptoTransform encryptor = aesObject.CreateEncryptor();
            byte[] result = null;

            try
            {
                result = encryptor.TransformFinalBlock(byteInput, 0, byteInput.Length);
            }
            catch (Exception e) // if encryption fails
            {
                Console.WriteLine(e.Message); // display the cause
            }

            return result;
        }

        
    }
}
