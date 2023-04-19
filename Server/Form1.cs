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

        private string RSAxmlKey3072_enc_dec;
        private string RSAxmlKey3072_sign_verif;

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
            AddMessage("Following disconnected due to termination!");
            for (int i = 0; i < socketList.Count; i++)
            {
                AddMessage(" - " + getClientIp(socketList[i].RemoteEndPoint));
                socketList[i].Close();
            }
            serverSocket.Close();
            socketList.Clear();
            AddMessage("Server has stopped!");
            AddMessage("-------------------");
            btnStop.Enabled = false;
            btnStart.Enabled = true;
            txtPort.ReadOnly = false;
            txtPort.Enabled = true;
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

        private void Receive()
        {
            Socket s = socketList[socketList.Count - 1];
            bool connected = true;

            while (connected && !terminating)
            {
                try
                {
                    Byte[] buffer = new Byte[3072];
                    s.Receive(buffer);

                    string incomingMessageHexS = Encoding.Default.GetString(buffer);
                    incomingMessageHexS = incomingMessageHexS.Substring(0, incomingMessageHexS.IndexOf("\0"));

                    byte[] incomingMessageHex = hexStringToByteArray(incomingMessageHexS);
                    string incomingMessage = Encoding.Default.GetString(incomingMessageHex);


                    byte[] decrypt = decryptWithRSA(incomingMessage, 3072, RSAxmlKey3072_enc_dec);
                    string decryptS = Encoding.Default.GetString(decrypt);
                    //AddMessage(getClientIp(s.RemoteEndPoint) + " sent request with following payload: " + decryptS);

                    if (decryptS.IndexOf(":") == -1)
                    {
                        // Login Phase
                        AddMessage(getClientIp(s.RemoteEndPoint) + " is trying to login!");
                    }
                    else
                    {
                        // Enroll Phase;
                        AddMessage(getClientIp(s.RemoteEndPoint) + " is trying to enroll!");

                        string[] data = decryptS.Split(':');
                        string response;
                        if (userExist(data[1]))
                        {
                            response = "error";
                        }
                        else
                        {
                            response = "success";
                            write2DB(decryptS);
                        }
                        byte[] signedResponse = signWithRSA(response, 3072, RSAxmlKey3072_sign_verif);
                        string signedResponseHexS = generateHexStringFromByteArray(signedResponse) + '\0';
                        byte[] signedResponseHex = Encoding.ASCII.GetBytes(signedResponseHexS);

                        s.Send(signedResponseHex);

                        AddMessage(getClientIp(s.RemoteEndPoint) + "'s enrollment response: " + response);
                        //AddMessage(getClientIp(s.RemoteEndPoint) + "'s enrollment response in hex format: " + generateHexStringFromByteArray(signedResponse));

                        AddMessage(getClientIp(s.RemoteEndPoint) + " disconnected!");

                        s.Close();
                        socketList.Remove(s);
                        connected = false;
                    }
                }
                catch (Exception ex)
                {
                    if (!terminating)
                    {
                        AddMessage(getClientIp(s.RemoteEndPoint) + ": Error " + ex.Message);
                        AddMessage(getClientIp(s.RemoteEndPoint) + " disconnected!");
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
                        if(data[0] == s)
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
            if(File.Exists(db) && !userExist(s))
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
                result = rsaObject.SignData(byteInput, "SHA256");
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }
    }
}
