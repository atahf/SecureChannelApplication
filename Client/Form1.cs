using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Windows.Forms;
using System.Threading;
using System.Security.Cryptography;

namespace Secure_Channel_Client
{
    public partial class Form1 : Form
    {
        private bool terminating = false;
        private bool connected = false;
        private Socket socket = null;

        private string channel = "";

        private string RSAxmlKey3072_encryption;
        private string RSAxmlKey3072_sign;

        public Form1()
        {
            using (System.IO.StreamReader fileReader =
            new System.IO.StreamReader("../../server_enc_dec_pub.txt"))
            {
                RSAxmlKey3072_encryption = fileReader.ReadLine();
            }

            using (System.IO.StreamReader fileReader =
            new System.IO.StreamReader("../../server_sign_verify_pub.txt"))
            {
                RSAxmlKey3072_sign = fileReader.ReadLine();
            }

            Control.CheckForIllegalCrossThreadCalls = false;
            this.FormClosing += new FormClosingEventHandler(Form1_FormClosing);
            InitializeComponent();
        }

        private void btnEnroll_Click(object sender, EventArgs e)
        {
            socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            string ip = textServerIP.Text;
            string portNum = textServerPort.Text;
            int port_num;
            if (Int32.TryParse(portNum, out port_num))
            {
                try
                {
                    socket.Connect(ip, port_num);
                    btnEnroll.Enabled = false;
                    textUser.ReadOnly = true;
                    textPass.ReadOnly = true;
                    textServerIP.ReadOnly = true;
                    textServerPort.ReadOnly = true;
                    connected = true;
                    AddEnrollLog("Connected to the server.");

                    Thread receiveThread = new Thread(new ThreadStart(Enroll));
                    receiveThread.Start();
                }
                catch
                {
                    AddEnrollLog("Could not connect to the server.");
                }

            }
            else
            {
                AddEnrollLog("Check the port number.");
            }
        }

        // Enrollment Phase
        private void Enroll()
        {
            if (connected)
            {
                try
                {
                    string pass = textPass.Text;
                    string user = textUser.Text;

                    byte[] hashedPass = hashWithSHA512(pass);
                    string hashedPassS = generateHexStringFromByteArray(hashedPass);
                    AddEnrollLog("you hashed password in hex format: " + hashedPassS);

                    string enrollMsg = hashedPassS + ":" + user + ":" + channel;
                    byte[] enrollMsgEncrypted = encryptWithRSA(enrollMsg, 3072, RSAxmlKey3072_encryption);
                    string enrollMsgEncryptedHexS = generateHexStringFromByteArray(enrollMsgEncrypted) + '\0';
                    byte[] payload = Encoding.ASCII.GetBytes(enrollMsgEncryptedHexS);

                    socket.Send(payload);

                    Byte[] buffer = new Byte[3072];
                    socket.Receive(buffer);

                    string incomingMessageHexS = Encoding.Default.GetString(buffer);
                    incomingMessageHexS = incomingMessageHexS.Substring(0, incomingMessageHexS.IndexOf("\0"));

                    byte[] incomingMessageHex = hexStringToByteArray(incomingMessageHexS);
                    string incomingMessage = Encoding.Default.GetString(incomingMessageHex);

                    bool verifiedError = verifyWithRSA("error", 3072, RSAxmlKey3072_sign, incomingMessageHex);
                    bool verifiedSuccess = verifyWithRSA("success", 3072, RSAxmlKey3072_sign, incomingMessageHex);

                    if (verifiedError)
                    {
                        AddEnrollLog("This username is taken, please write a new username!");
                        textUser.ReadOnly = false;
                        textUser.Clear();
                        btnEnroll.Enabled = true;

                        socket.Close();
                        connected = false;
                    }
                    else if (verifiedSuccess)
                    {
                        AddEnrollLog("You have successfully enrolled to " + channel + " channel, now you can go to Login tab and login with your username and password!");
                        btnEnroll.Enabled = true;
                        textUser.ReadOnly = false;
                        textPass.ReadOnly = false;
                        textServerIP.ReadOnly = false;
                        textServerPort.ReadOnly = false;

                        socket.Close();
                        connected = false;
                    }
                    else
                    {
                        AddEnrollLog("this is unexpected!");
                    }
                }
                catch
                {
                    if (!terminating)
                    {
                        AddEnrollLog("Connection has lost with the server.");
                    }

                    socket.Close();
                    connected = false;
                }
            }
        }

        private void btnLogin_Click(object sender, EventArgs e)
        {
            socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            string ip = textServerIP2.Text;
            string portNum = textServerPort2.Text;
            int port_num;
            if (Int32.TryParse(portNum, out port_num))
            {
                try
                {
                    socket.Connect(ip, port_num);
                    btnEnroll.Enabled = false;
                    textUser.ReadOnly = true;
                    textPass.ReadOnly = true;
                    textServerIP.ReadOnly = true;
                    textServerPort.ReadOnly = true;
                    connected = true;
                    AddEnrollLog("Connected to the server.");

                    Thread receiveThread = new Thread(new ThreadStart(Login));
                    receiveThread.Start();
                }
                catch
                {
                    AddEnrollLog("Could not connect to the server.");
                }

            }
            else
            {
                AddEnrollLog("Check the port number.");
            }
        }

        // Login Phase
        private void Login()
        {
            if (connected)
            {
                try
                {
                    string pass = textPass2.Text;
                    string user = textUser2.Text;


                }
                catch
                {
                    if (!terminating)
                    {
                        AddEnrollLog("Connection has lost with the server.");
                    }

                    socket.Close();
                    connected = false;
                }
            }
        }

        private void AddEnrollLog(string message)
        {
            if (textEnrollLog.InvokeRequired)
            {
                textEnrollLog.Invoke(new Action<string>(AddEnrollLog), message);
            }
            else
            {
                textEnrollLog.AppendText(message + Environment.NewLine);
            }
        }

        private void channelButtonIF100_CheckedChanged(object sender, EventArgs e)
        {
            if (channelButtonIF100.Checked)
            {
                channel = channelButtonIF100.Text;
            }
        }

        private void channelButtonMATH101_CheckedChanged(object sender, EventArgs e)
        {
            if (channelButtonMATH101.Checked)
            {
                channel = channelButtonMATH101.Text;
            }
        }

        private void channelButtonSPS101_CheckedChanged(object sender, EventArgs e)
        {
            if (channelButtonSPS101.Checked)
            {
                channel = channelButtonSPS101.Text;
            }
        }

        private void AddLoginLog(string message)
        {
            if (textEnrollLog.InvokeRequired)
            {
                textLoginLog.Invoke(new Action<string>(AddLoginLog), message);
            }
            else
            {
                textLoginLog.AppendText(message + Environment.NewLine);
            }
        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (socket != null)
            {
                socket.Close();
            }
            connected = false;
            terminating = true;
            Environment.Exit(0);
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

        // hash function: SHA-512
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

        // RSA encryption with varying bit length
        static byte[] encryptWithRSA(string input, int algoLength, string xmlStringKey)
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
                //true flag is set to perform direct RSA encryption using OAEP padding
                result = rsaObject.Encrypt(byteInput, true);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }

        // verifying with RSA
        static bool verifyWithRSA(string input, int algoLength, string xmlString, byte[] signature)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create RSA object from System.Security.Cryptography
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(algoLength);
            // set RSA object with xml string
            rsaObject.FromXmlString(xmlString);
            bool result = false;

            try
            {
                result = rsaObject.VerifyData(byteInput, "SHA256", signature);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }
    }
}
