namespace Secure_Channel_Server
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
            this.btnStart = new System.Windows.Forms.Button();
            this.btnStop = new System.Windows.Forms.Button();
            this.txtPort = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.txtOutput = new System.Windows.Forms.TextBox();
            this.mathSecretKey = new System.Windows.Forms.TextBox();
            this.spsSecretKey = new System.Windows.Forms.TextBox();
            this.ifSecretKey = new System.Windows.Forms.TextBox();
            this.mathKeyGenBtn = new System.Windows.Forms.Button();
            this.spsKeyGenBtn = new System.Windows.Forms.Button();
            this.ifKeyGenBtn = new System.Windows.Forms.Button();
            this.label2 = new System.Windows.Forms.Label();
            this.label3 = new System.Windows.Forms.Label();
            this.label4 = new System.Windows.Forms.Label();
            this.ifChannel = new System.Windows.Forms.RichTextBox();
            this.mathChannel = new System.Windows.Forms.RichTextBox();
            this.spsChannel = new System.Windows.Forms.RichTextBox();
            this.label5 = new System.Windows.Forms.Label();
            this.label6 = new System.Windows.Forms.Label();
            this.label7 = new System.Windows.Forms.Label();
            this.SuspendLayout();
            // 
            // btnStart
            // 
            this.btnStart.BackColor = System.Drawing.Color.LightGreen;
            this.btnStart.Cursor = System.Windows.Forms.Cursors.Hand;
            this.btnStart.Location = new System.Drawing.Point(694, 17);
            this.btnStart.Name = "btnStart";
            this.btnStart.Size = new System.Drawing.Size(75, 29);
            this.btnStart.TabIndex = 0;
            this.btnStart.Text = "Start";
            this.btnStart.UseVisualStyleBackColor = false;
            this.btnStart.Click += new System.EventHandler(this.btnStart_Click);
            // 
            // btnStop
            // 
            this.btnStop.BackColor = System.Drawing.Color.Red;
            this.btnStop.Cursor = System.Windows.Forms.Cursors.Hand;
            this.btnStop.Enabled = false;
            this.btnStop.Location = new System.Drawing.Point(810, 17);
            this.btnStop.Name = "btnStop";
            this.btnStop.Size = new System.Drawing.Size(75, 29);
            this.btnStop.TabIndex = 0;
            this.btnStop.Text = "Stop";
            this.btnStop.UseVisualStyleBackColor = false;
            this.btnStop.Click += new System.EventHandler(this.btnStop_Click);
            // 
            // txtPort
            // 
            this.txtPort.Location = new System.Drawing.Point(430, 22);
            this.txtPort.Name = "txtPort";
            this.txtPort.Size = new System.Drawing.Size(61, 20);
            this.txtPort.TabIndex = 1;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(357, 25);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(67, 13);
            this.label1.TabIndex = 2;
            this.label1.Text = "Port number:";
            // 
            // txtOutput
            // 
            this.txtOutput.Location = new System.Drawing.Point(12, 61);
            this.txtOutput.Multiline = true;
            this.txtOutput.Name = "txtOutput";
            this.txtOutput.ReadOnly = true;
            this.txtOutput.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.txtOutput.Size = new System.Drawing.Size(886, 492);
            this.txtOutput.TabIndex = 2;
            // 
            // mathSecretKey
            // 
            this.mathSecretKey.Location = new System.Drawing.Point(29, 629);
            this.mathSecretKey.Name = "mathSecretKey";
            this.mathSecretKey.Size = new System.Drawing.Size(184, 20);
            this.mathSecretKey.TabIndex = 3;
            // 
            // spsSecretKey
            // 
            this.spsSecretKey.Location = new System.Drawing.Point(350, 629);
            this.spsSecretKey.Name = "spsSecretKey";
            this.spsSecretKey.Size = new System.Drawing.Size(184, 20);
            this.spsSecretKey.TabIndex = 4;
            // 
            // ifSecretKey
            // 
            this.ifSecretKey.Location = new System.Drawing.Point(714, 629);
            this.ifSecretKey.Name = "ifSecretKey";
            this.ifSecretKey.Size = new System.Drawing.Size(184, 20);
            this.ifSecretKey.TabIndex = 5;
            // 
            // mathKeyGenBtn
            // 
            this.mathKeyGenBtn.Location = new System.Drawing.Point(61, 665);
            this.mathKeyGenBtn.Name = "mathKeyGenBtn";
            this.mathKeyGenBtn.Size = new System.Drawing.Size(125, 29);
            this.mathKeyGenBtn.TabIndex = 6;
            this.mathKeyGenBtn.Text = "Generate Key";
            this.mathKeyGenBtn.UseVisualStyleBackColor = true;
            this.mathKeyGenBtn.Click += new System.EventHandler(this.mathKeyGenBtn_Click);
            // 
            // spsKeyGenBtn
            // 
            this.spsKeyGenBtn.Location = new System.Drawing.Point(388, 665);
            this.spsKeyGenBtn.Name = "spsKeyGenBtn";
            this.spsKeyGenBtn.Size = new System.Drawing.Size(125, 29);
            this.spsKeyGenBtn.TabIndex = 7;
            this.spsKeyGenBtn.Text = "Generate Key";
            this.spsKeyGenBtn.UseVisualStyleBackColor = true;
            this.spsKeyGenBtn.Click += new System.EventHandler(this.spsKeyGenBtn_Click);
            // 
            // ifKeyGenBtn
            // 
            this.ifKeyGenBtn.Location = new System.Drawing.Point(746, 665);
            this.ifKeyGenBtn.Name = "ifKeyGenBtn";
            this.ifKeyGenBtn.Size = new System.Drawing.Size(125, 29);
            this.ifKeyGenBtn.TabIndex = 8;
            this.ifKeyGenBtn.Text = "Generate Key";
            this.ifKeyGenBtn.UseVisualStyleBackColor = true;
            this.ifKeyGenBtn.Click += new System.EventHandler(this.ifKeyGenBtn_Click);
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(39, 603);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(161, 13);
            this.label2.TabIndex = 9;
            this.label2.Text = "Master Secret Key for MATH101";
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(362, 603);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(151, 13);
            this.label3.TabIndex = 10;
            this.label3.Text = "Master Secret Key for SPS101";
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(732, 603);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(139, 13);
            this.label4.TabIndex = 11;
            this.label4.Text = "Master Secret Key for IF100";
            // 
            // ifChannel
            // 
            this.ifChannel.Location = new System.Drawing.Point(918, 61);
            this.ifChannel.Name = "ifChannel";
            this.ifChannel.Size = new System.Drawing.Size(321, 301);
            this.ifChannel.TabIndex = 12;
            this.ifChannel.Text = "";
            // 
            // mathChannel
            // 
            this.mathChannel.Location = new System.Drawing.Point(918, 393);
            this.mathChannel.Name = "mathChannel";
            this.mathChannel.Size = new System.Drawing.Size(321, 301);
            this.mathChannel.TabIndex = 13;
            this.mathChannel.Text = "";
            // 
            // spsChannel
            // 
            this.spsChannel.Location = new System.Drawing.Point(1245, 222);
            this.spsChannel.Name = "spsChannel";
            this.spsChannel.Size = new System.Drawing.Size(321, 301);
            this.spsChannel.TabIndex = 14;
            this.spsChannel.Text = "";
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(1032, 45);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(79, 13);
            this.label5.TabIndex = 15;
            this.label5.Text = "IF 100 Channel";
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Location = new System.Drawing.Point(1032, 377);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(101, 13);
            this.label6.TabIndex = 16;
            this.label6.Text = "MATH 101 Channel";
            // 
            // label7
            // 
            this.label7.AutoSize = true;
            this.label7.Location = new System.Drawing.Point(1371, 206);
            this.label7.Name = "label7";
            this.label7.Size = new System.Drawing.Size(91, 13);
            this.label7.TabIndex = 17;
            this.label7.Text = "SPS 101 Channel";
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.BackColor = System.Drawing.SystemColors.ActiveCaption;
            this.ClientSize = new System.Drawing.Size(1572, 706);
            this.Controls.Add(this.label7);
            this.Controls.Add(this.label6);
            this.Controls.Add(this.label5);
            this.Controls.Add(this.spsChannel);
            this.Controls.Add(this.mathChannel);
            this.Controls.Add(this.ifChannel);
            this.Controls.Add(this.label4);
            this.Controls.Add(this.label3);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.ifKeyGenBtn);
            this.Controls.Add(this.spsKeyGenBtn);
            this.Controls.Add(this.mathKeyGenBtn);
            this.Controls.Add(this.ifSecretKey);
            this.Controls.Add(this.spsSecretKey);
            this.Controls.Add(this.mathSecretKey);
            this.Controls.Add(this.txtOutput);
            this.Controls.Add(this.btnStop);
            this.Controls.Add(this.btnStart);
            this.Controls.Add(this.txtPort);
            this.Controls.Add(this.label1);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.Margin = new System.Windows.Forms.Padding(4);
            this.MaximizeBox = false;
            this.Name = "Form1";
            this.Text = "Secure Channel Server";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button btnStart;
        private System.Windows.Forms.Button btnStop;
        private System.Windows.Forms.TextBox txtPort;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TextBox txtOutput;
        private System.Windows.Forms.TextBox mathSecretKey;
        private System.Windows.Forms.TextBox spsSecretKey;
        private System.Windows.Forms.TextBox ifSecretKey;
        private System.Windows.Forms.Button mathKeyGenBtn;
        private System.Windows.Forms.Button spsKeyGenBtn;
        private System.Windows.Forms.Button ifKeyGenBtn;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.RichTextBox ifChannel;
        private System.Windows.Forms.RichTextBox mathChannel;
        private System.Windows.Forms.RichTextBox spsChannel;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.Label label6;
        private System.Windows.Forms.Label label7;
    }
}
