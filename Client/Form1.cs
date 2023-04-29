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

        private bool loggedIn = false;
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
            if (loggedIn)
            {
                socket.Close();
                loggedIn = false;
                connected = false;
                btnLogin.Text = "Login";
                btnLogin.BackColor = Color.LightGreen;
            }
            else
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
                        btnLogin.Text = "Disconnect";
                        btnLogin.BackColor = Color.Red;
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

                    byte[] hashedPass = hashWithSHA512(pass);

                    byte[] lowerQuarter = new byte[16];
                    Array.Copy(hashedPass, 0, lowerQuarter, 0, 16);

                    byte[] AES128key = new byte[16];
                    byte[] AES128IV = new byte[16];

                    Array.Copy(hashedPass, 0, AES128key, 0, 16);
                    Array.Copy(hashedPass, 16, AES128IV, 0, 16);

                    string authReqS = "auth:" + user;
                    byte[] authReq = Encoding.ASCII.GetBytes(authReqS);
                    socket.Send(authReq);

                    Byte[] buffer = new Byte[16];
                    socket.Receive(buffer);
                    string rndNum = Encoding.Default.GetString(buffer);

                    byte[] HMACrndNum = applyHMACwithSHA512(rndNum, lowerQuarter);
                    socket.Send(HMACrndNum);

                    Byte[] auth_data_buff = new Byte[3072];
                    socket.Receive(auth_data_buff);

                    string auth_dataS = Encoding.Default.GetString(auth_data_buff);

                    string enc_msg = auth_dataS.Substring(0, auth_dataS.IndexOf(":auth:"));
                    string msg_sign = auth_dataS.Substring(auth_dataS.IndexOf(":auth:") + 6);
                    msg_sign = msg_sign.Substring(0, msg_sign.IndexOf("\0"));
                    byte[] sign = hexStringToByteArray(msg_sign);

                    bool verif = verifyWithRSA(enc_msg, 3072, RSAxmlKey3072_sign, sign);

                    if(verif)
                    {
                        if(enc_msg == "no_user")
                        {
                            AddLoginLog("wrong username!");
                        }
                        else
                        {
                            byte[] enc_msg_hex = hexStringToByteArray(enc_msg);
                            string enc_res = Encoding.Default.GetString(enc_msg_hex);

                            try
                            {
                                byte[] enc_suc = decryptWithAES128(enc_res, AES128key, AES128IV);
                                string response = Encoding.Default.GetString(enc_suc);

                                AddLoginLog(response);
                                if (response == "success")
                                {
                                    AddLoginLog("You have successfully logged in!");
                                    loggedIn = true;

                                    while (true) { }
                                }
                                else if (response == "already")
                                {
                                    AddLoginLog("there is already a user online with same username!");
                                }
                                else
                                {
                                    AddLoginLog("this should never happen!");

                                    socket.Close();
                                    connected = false;
                                }
                            }
                            catch (Exception ex)
                            {
                                AddLoginLog("wrong  password, try again!");


                                AddEnrollLog("Connected to the server.");

                                socket.Close();

                                btnEnroll.Enabled = true;
                                textPass.ReadOnly = false;
                                connected = false;
                                btnLogin.Text = "Login";
                                btnLogin.BackColor = Color.LightGreen;
                            }
                        }
                    }
                    else
                    {
                        AddLoginLog("something went wrong!");

                        socket.Close();
                        connected = false;
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
                result = rsaObject.VerifyData(byteInput, "SHA512", signature);
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
        static byte[] decryptWithAES128(string input, byte[] key, byte[] IV)
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
            // aesObject.FeedbackSize = 128;
            // set the key
            aesObject.Key = key;
            // set the IV
            aesObject.IV = IV;
            // create an encryptor with the settings provided
            ICryptoTransform decryptor = aesObject.CreateDecryptor();
            byte[] result = null;

            try
            {
                result = decryptor.TransformFinalBlock(byteInput, 0, byteInput.Length);
            }
            catch (Exception e) // if encryption fails
            {
                Console.WriteLine(e.Message); // display the cause
            }

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
