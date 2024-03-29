﻿namespace Secure_Channel_Client
{
    partial class Form1
    {
        private System.ComponentModel.IContainer components = null;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        private void InitializeComponent()
        {
            this.tabControl = new System.Windows.Forms.TabControl();
            this.tabEnroll = new System.Windows.Forms.TabPage();
            this.btnEnroll = new System.Windows.Forms.Button();
            this.lblChannel = new System.Windows.Forms.Label();
            this.channelButtonSPS101 = new System.Windows.Forms.RadioButton();
            this.channelButtonMATH101 = new System.Windows.Forms.RadioButton();
            this.channelButtonIF100 = new System.Windows.Forms.RadioButton();
            this.textEnrollLog = new System.Windows.Forms.TextBox();
            this.textServerPort = new System.Windows.Forms.TextBox();
            this.textServerIP = new System.Windows.Forms.TextBox();
            this.textPass = new System.Windows.Forms.TextBox();
            this.textUser = new System.Windows.Forms.TextBox();
            this.lblServerPort = new System.Windows.Forms.Label();
            this.lblServerIp = new System.Windows.Forms.Label();
            this.lblPass = new System.Windows.Forms.Label();
            this.lblUser = new System.Windows.Forms.Label();
            this.tabLogin = new System.Windows.Forms.TabPage();
            this.disconnectButton = new System.Windows.Forms.Button();
            this.btnLogin = new System.Windows.Forms.Button();
            this.textLoginLog = new System.Windows.Forms.TextBox();
            this.textServerPort2 = new System.Windows.Forms.TextBox();
            this.textServerIP2 = new System.Windows.Forms.TextBox();
            this.textPass2 = new System.Windows.Forms.TextBox();
            this.textUser2 = new System.Windows.Forms.TextBox();
            this.lblServerPort2 = new System.Windows.Forms.Label();
            this.lblServerIP2 = new System.Windows.Forms.Label();
            this.lblPass2 = new System.Windows.Forms.Label();
            this.lblUser2 = new System.Windows.Forms.Label();
            this.generalChannel = new System.Windows.Forms.RichTextBox();
            this.messageTbs = new System.Windows.Forms.TextBox();
            this.sendMessageBtn = new System.Windows.Forms.Button();
            this.label4 = new System.Windows.Forms.Label();
            this.tabControl.SuspendLayout();
            this.tabEnroll.SuspendLayout();
            this.tabLogin.SuspendLayout();
            this.SuspendLayout();
            // 
            // tabControl
            // 
            this.tabControl.Controls.Add(this.tabEnroll);
            this.tabControl.Controls.Add(this.tabLogin);
            this.tabControl.Location = new System.Drawing.Point(12, 12);
            this.tabControl.Name = "tabControl";
            this.tabControl.SelectedIndex = 0;
            this.tabControl.Size = new System.Drawing.Size(1215, 951);
            this.tabControl.TabIndex = 0;
            // 
            // tabEnroll
            // 
            this.tabEnroll.Controls.Add(this.btnEnroll);
            this.tabEnroll.Controls.Add(this.lblChannel);
            this.tabEnroll.Controls.Add(this.channelButtonSPS101);
            this.tabEnroll.Controls.Add(this.channelButtonMATH101);
            this.tabEnroll.Controls.Add(this.channelButtonIF100);
            this.tabEnroll.Controls.Add(this.textEnrollLog);
            this.tabEnroll.Controls.Add(this.textServerPort);
            this.tabEnroll.Controls.Add(this.textServerIP);
            this.tabEnroll.Controls.Add(this.textPass);
            this.tabEnroll.Controls.Add(this.textUser);
            this.tabEnroll.Controls.Add(this.lblServerPort);
            this.tabEnroll.Controls.Add(this.lblServerIp);
            this.tabEnroll.Controls.Add(this.lblPass);
            this.tabEnroll.Controls.Add(this.lblUser);
            this.tabEnroll.Location = new System.Drawing.Point(4, 22);
            this.tabEnroll.Name = "tabEnroll";
            this.tabEnroll.Padding = new System.Windows.Forms.Padding(3);
            this.tabEnroll.Size = new System.Drawing.Size(1207, 925);
            this.tabEnroll.TabIndex = 0;
            this.tabEnroll.Text = "Enroll";
            this.tabEnroll.UseVisualStyleBackColor = true;
            // 
            // btnEnroll
            // 
            this.btnEnroll.Location = new System.Drawing.Point(157, 295);
            this.btnEnroll.Name = "btnEnroll";
            this.btnEnroll.Size = new System.Drawing.Size(75, 23);
            this.btnEnroll.TabIndex = 13;
            this.btnEnroll.Text = "Enroll";
            this.btnEnroll.UseVisualStyleBackColor = true;
            this.btnEnroll.Click += new System.EventHandler(this.btnEnroll_Click);
            // 
            // lblChannel
            // 
            this.lblChannel.AutoSize = true;
            this.lblChannel.Location = new System.Drawing.Point(92, 134);
            this.lblChannel.Name = "lblChannel";
            this.lblChannel.Size = new System.Drawing.Size(211, 13);
            this.lblChannel.TabIndex = 12;
            this.lblChannel.Text = "Choose the channel you want to subscribe!";
            // 
            // channelButtonSPS101
            // 
            this.channelButtonSPS101.AutoSize = true;
            this.channelButtonSPS101.Location = new System.Drawing.Point(249, 162);
            this.channelButtonSPS101.Name = "channelButtonSPS101";
            this.channelButtonSPS101.Size = new System.Drawing.Size(64, 17);
            this.channelButtonSPS101.TabIndex = 11;
            this.channelButtonSPS101.TabStop = true;
            this.channelButtonSPS101.Text = "SPS101";
            this.channelButtonSPS101.UseVisualStyleBackColor = true;
            this.channelButtonSPS101.CheckedChanged += new System.EventHandler(this.channelButtonSPS101_CheckedChanged);
            // 
            // channelButtonMATH101
            // 
            this.channelButtonMATH101.AutoSize = true;
            this.channelButtonMATH101.Location = new System.Drawing.Point(158, 162);
            this.channelButtonMATH101.Name = "channelButtonMATH101";
            this.channelButtonMATH101.Size = new System.Drawing.Size(74, 17);
            this.channelButtonMATH101.TabIndex = 10;
            this.channelButtonMATH101.TabStop = true;
            this.channelButtonMATH101.Text = "MATH101";
            this.channelButtonMATH101.UseVisualStyleBackColor = true;
            this.channelButtonMATH101.CheckedChanged += new System.EventHandler(this.channelButtonMATH101_CheckedChanged);
            // 
            // channelButtonIF100
            // 
            this.channelButtonIF100.AutoSize = true;
            this.channelButtonIF100.Location = new System.Drawing.Point(78, 162);
            this.channelButtonIF100.Name = "channelButtonIF100";
            this.channelButtonIF100.Size = new System.Drawing.Size(52, 17);
            this.channelButtonIF100.TabIndex = 9;
            this.channelButtonIF100.TabStop = true;
            this.channelButtonIF100.Text = "IF100";
            this.channelButtonIF100.UseVisualStyleBackColor = true;
            this.channelButtonIF100.CheckedChanged += new System.EventHandler(this.channelButtonIF100_CheckedChanged);
            // 
            // textEnrollLog
            // 
            this.textEnrollLog.Location = new System.Drawing.Point(433, 23);
            this.textEnrollLog.Multiline = true;
            this.textEnrollLog.Name = "textEnrollLog";
            this.textEnrollLog.ReadOnly = true;
            this.textEnrollLog.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.textEnrollLog.Size = new System.Drawing.Size(769, 522);
            this.textEnrollLog.TabIndex = 8;
            // 
            // textServerPort
            // 
            this.textServerPort.Location = new System.Drawing.Point(276, 77);
            this.textServerPort.Name = "textServerPort";
            this.textServerPort.Size = new System.Drawing.Size(100, 20);
            this.textServerPort.TabIndex = 7;
            // 
            // textServerIP
            // 
            this.textServerIP.Location = new System.Drawing.Point(276, 23);
            this.textServerIP.Name = "textServerIP";
            this.textServerIP.Size = new System.Drawing.Size(100, 20);
            this.textServerIP.TabIndex = 6;
            // 
            // textPass
            // 
            this.textPass.Location = new System.Drawing.Point(78, 77);
            this.textPass.Name = "textPass";
            this.textPass.PasswordChar = '*';
            this.textPass.Size = new System.Drawing.Size(100, 20);
            this.textPass.TabIndex = 5;
            // 
            // textUser
            // 
            this.textUser.Location = new System.Drawing.Point(78, 23);
            this.textUser.Name = "textUser";
            this.textUser.Size = new System.Drawing.Size(100, 20);
            this.textUser.TabIndex = 4;
            // 
            // lblServerPort
            // 
            this.lblServerPort.AutoSize = true;
            this.lblServerPort.Location = new System.Drawing.Point(210, 80);
            this.lblServerPort.Name = "lblServerPort";
            this.lblServerPort.Size = new System.Drawing.Size(60, 13);
            this.lblServerPort.TabIndex = 3;
            this.lblServerPort.Text = "Server Port";
            // 
            // lblServerIp
            // 
            this.lblServerIp.AutoSize = true;
            this.lblServerIp.Location = new System.Drawing.Point(210, 26);
            this.lblServerIp.Name = "lblServerIp";
            this.lblServerIp.Size = new System.Drawing.Size(51, 13);
            this.lblServerIp.TabIndex = 2;
            this.lblServerIp.Text = "Server IP";
            // 
            // lblPass
            // 
            this.lblPass.AutoSize = true;
            this.lblPass.Location = new System.Drawing.Point(17, 80);
            this.lblPass.Name = "lblPass";
            this.lblPass.Size = new System.Drawing.Size(53, 13);
            this.lblPass.TabIndex = 1;
            this.lblPass.Text = "Password";
            // 
            // lblUser
            // 
            this.lblUser.AutoSize = true;
            this.lblUser.Location = new System.Drawing.Point(17, 26);
            this.lblUser.Name = "lblUser";
            this.lblUser.Size = new System.Drawing.Size(55, 13);
            this.lblUser.TabIndex = 0;
            this.lblUser.Text = "Username";
            // 
            // tabLogin
            // 
            this.tabLogin.Controls.Add(this.label4);
            this.tabLogin.Controls.Add(this.sendMessageBtn);
            this.tabLogin.Controls.Add(this.disconnectButton);
            this.tabLogin.Controls.Add(this.messageTbs);
            this.tabLogin.Controls.Add(this.btnLogin);
            this.tabLogin.Controls.Add(this.textLoginLog);
            this.tabLogin.Controls.Add(this.textServerPort2);
            this.tabLogin.Controls.Add(this.textServerIP2);
            this.tabLogin.Controls.Add(this.textPass2);
            this.tabLogin.Controls.Add(this.generalChannel);
            this.tabLogin.Controls.Add(this.textUser2);
            this.tabLogin.Controls.Add(this.lblServerPort2);
            this.tabLogin.Controls.Add(this.lblServerIP2);
            this.tabLogin.Controls.Add(this.lblPass2);
            this.tabLogin.Controls.Add(this.lblUser2);
            this.tabLogin.Location = new System.Drawing.Point(4, 22);
            this.tabLogin.Name = "tabLogin";
            this.tabLogin.Padding = new System.Windows.Forms.Padding(3);
            this.tabLogin.Size = new System.Drawing.Size(1207, 925);
            this.tabLogin.TabIndex = 1;
            this.tabLogin.Text = "Login";
            this.tabLogin.UseVisualStyleBackColor = true;
            // 
            // disconnectButton
            // 
            this.disconnectButton.BackColor = System.Drawing.Color.Red;
            this.disconnectButton.Cursor = System.Windows.Forms.Cursors.Hand;
            this.disconnectButton.Enabled = false;
            this.disconnectButton.Location = new System.Drawing.Point(207, 390);
            this.disconnectButton.Name = "disconnectButton";
            this.disconnectButton.Size = new System.Drawing.Size(90, 36);
            this.disconnectButton.TabIndex = 20;
            this.disconnectButton.Text = "disconnect";
            this.disconnectButton.UseVisualStyleBackColor = false;
            this.disconnectButton.Click += new System.EventHandler(this.disconnectButton_Click);
            // 
            // btnLogin
            // 
            this.btnLogin.BackColor = System.Drawing.Color.LightGreen;
            this.btnLogin.Cursor = System.Windows.Forms.Cursors.Hand;
            this.btnLogin.Location = new System.Drawing.Point(87, 390);
            this.btnLogin.Name = "btnLogin";
            this.btnLogin.Size = new System.Drawing.Size(90, 36);
            this.btnLogin.TabIndex = 19;
            this.btnLogin.Text = "Login";
            this.btnLogin.UseVisualStyleBackColor = false;
            this.btnLogin.Click += new System.EventHandler(this.btnLogin_Click);
            // 
            // textLoginLog
            // 
            this.textLoginLog.Location = new System.Drawing.Point(393, 22);
            this.textLoginLog.Multiline = true;
            this.textLoginLog.Name = "textLoginLog";
            this.textLoginLog.ReadOnly = true;
            this.textLoginLog.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.textLoginLog.Size = new System.Drawing.Size(809, 526);
            this.textLoginLog.TabIndex = 17;
            // 
            // textServerPort2
            // 
            this.textServerPort2.Location = new System.Drawing.Point(270, 96);
            this.textServerPort2.Name = "textServerPort2";
            this.textServerPort2.Size = new System.Drawing.Size(100, 20);
            this.textServerPort2.TabIndex = 16;
            // 
            // textServerIP2
            // 
            this.textServerIP2.Location = new System.Drawing.Point(270, 42);
            this.textServerIP2.Name = "textServerIP2";
            this.textServerIP2.Size = new System.Drawing.Size(100, 20);
            this.textServerIP2.TabIndex = 15;
            // 
            // textPass2
            // 
            this.textPass2.Location = new System.Drawing.Point(87, 96);
            this.textPass2.Name = "textPass2";
            this.textPass2.PasswordChar = '*';
            this.textPass2.Size = new System.Drawing.Size(100, 20);
            this.textPass2.TabIndex = 14;
            // 
            // textUser2
            // 
            this.textUser2.Location = new System.Drawing.Point(87, 42);
            this.textUser2.Name = "textUser2";
            this.textUser2.Size = new System.Drawing.Size(100, 20);
            this.textUser2.TabIndex = 13;
            // 
            // lblServerPort2
            // 
            this.lblServerPort2.AutoSize = true;
            this.lblServerPort2.Location = new System.Drawing.Point(204, 99);
            this.lblServerPort2.Name = "lblServerPort2";
            this.lblServerPort2.Size = new System.Drawing.Size(60, 13);
            this.lblServerPort2.TabIndex = 12;
            this.lblServerPort2.Text = "Server Port";
            // 
            // lblServerIP2
            // 
            this.lblServerIP2.AutoSize = true;
            this.lblServerIP2.Location = new System.Drawing.Point(204, 45);
            this.lblServerIP2.Name = "lblServerIP2";
            this.lblServerIP2.Size = new System.Drawing.Size(51, 13);
            this.lblServerIP2.TabIndex = 11;
            this.lblServerIP2.Text = "Server IP";
            // 
            // lblPass2
            // 
            this.lblPass2.AutoSize = true;
            this.lblPass2.Location = new System.Drawing.Point(26, 99);
            this.lblPass2.Name = "lblPass2";
            this.lblPass2.Size = new System.Drawing.Size(53, 13);
            this.lblPass2.TabIndex = 10;
            this.lblPass2.Text = "Password";
            // 
            // lblUser2
            // 
            this.lblUser2.AutoSize = true;
            this.lblUser2.Location = new System.Drawing.Point(26, 45);
            this.lblUser2.Name = "lblUser2";
            this.lblUser2.Size = new System.Drawing.Size(55, 13);
            this.lblUser2.TabIndex = 9;
            this.lblUser2.Text = "Username";
            // 
            // generalChannel
            // 
            this.generalChannel.BackColor = System.Drawing.SystemColors.ControlDark;
            this.generalChannel.Enabled = false;
            this.generalChannel.ForeColor = System.Drawing.SystemColors.WindowText;
            this.generalChannel.Location = new System.Drawing.Point(393, 572);
            this.generalChannel.Name = "generalChannel";
            this.generalChannel.Size = new System.Drawing.Size(809, 346);
            this.generalChannel.TabIndex = 2;
            this.generalChannel.Text = "";
            // 
            // messageTbs
            // 
            this.messageTbs.Enabled = false;
            this.messageTbs.Location = new System.Drawing.Point(33, 621);
            this.messageTbs.Multiline = true;
            this.messageTbs.Name = "messageTbs";
            this.messageTbs.Size = new System.Drawing.Size(337, 147);
            this.messageTbs.TabIndex = 7;
            // 
            // sendMessageBtn
            // 
            this.sendMessageBtn.Enabled = false;
            this.sendMessageBtn.Location = new System.Drawing.Point(98, 790);
            this.sendMessageBtn.Name = "sendMessageBtn";
            this.sendMessageBtn.Size = new System.Drawing.Size(182, 36);
            this.sendMessageBtn.TabIndex = 8;
            this.sendMessageBtn.Text = "Send";
            this.sendMessageBtn.UseVisualStyleBackColor = true;
            this.sendMessageBtn.Click += new System.EventHandler(this.sendMessageBtn_Click);
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(152, 605);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(87, 13);
            this.label4.TabIndex = 21;
            this.label4.Text = "Send a Message";
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.BackColor = System.Drawing.SystemColors.ActiveCaption;
            this.ClientSize = new System.Drawing.Size(1226, 964);
            this.Controls.Add(this.tabControl);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.Margin = new System.Windows.Forms.Padding(4);
            this.MaximizeBox = false;
            this.Name = "Form1";
            this.Text = "Secure Channel Client";
            this.tabControl.ResumeLayout(false);
            this.tabEnroll.ResumeLayout(false);
            this.tabEnroll.PerformLayout();
            this.tabLogin.ResumeLayout(false);
            this.tabLogin.PerformLayout();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.TabControl tabControl;
        private System.Windows.Forms.TabPage tabEnroll;
        private System.Windows.Forms.TabPage tabLogin;
        private System.Windows.Forms.Button btnEnroll;
        private System.Windows.Forms.Label lblChannel;
        private System.Windows.Forms.RadioButton channelButtonSPS101;
        private System.Windows.Forms.RadioButton channelButtonMATH101;
        private System.Windows.Forms.RadioButton channelButtonIF100;
        private System.Windows.Forms.TextBox textEnrollLog;
        private System.Windows.Forms.TextBox textServerPort;
        private System.Windows.Forms.TextBox textServerIP;
        private System.Windows.Forms.TextBox textPass;
        private System.Windows.Forms.TextBox textUser;
        private System.Windows.Forms.Label lblServerPort;
        private System.Windows.Forms.Label lblServerIp;
        private System.Windows.Forms.Label lblPass;
        private System.Windows.Forms.Label lblUser;
        private System.Windows.Forms.Button btnLogin;
        private System.Windows.Forms.TextBox textLoginLog;
        private System.Windows.Forms.TextBox textServerPort2;
        private System.Windows.Forms.TextBox textServerIP2;
        private System.Windows.Forms.TextBox textPass2;
        private System.Windows.Forms.TextBox textUser2;
        private System.Windows.Forms.Label lblServerPort2;
        private System.Windows.Forms.Label lblServerIP2;
        private System.Windows.Forms.Label lblPass2;
        private System.Windows.Forms.Label lblUser2;
        private System.Windows.Forms.Button disconnectButton;
        private System.Windows.Forms.RichTextBox generalChannel;
        private System.Windows.Forms.TextBox messageTbs;
        private System.Windows.Forms.Button sendMessageBtn;
        private System.Windows.Forms.Label label4;
    }
}
