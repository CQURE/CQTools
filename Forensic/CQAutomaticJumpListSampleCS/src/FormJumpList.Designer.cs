namespace Cqure.Forensics.AutomaticDestinations
{
  partial class FormJumpList
  {
    /// <summary>
    /// Required designer variable.
    /// </summary>
    private System.ComponentModel.IContainer components = null;

    /// <summary>
    /// Clean up any resources being used.
    /// </summary>
    /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
    protected override void Dispose(bool disposing)
    {
      if (disposing && (components != null))
      {
        components.Dispose();
      }
      base.Dispose(disposing);
    }

    #region Windows Form Designer generated code

    /// <summary>
    /// Required method for Designer support - do not modify
    /// the contents of this method with the code editor.
    /// </summary>
    private void InitializeComponent()
    {
      this.label1 = new System.Windows.Forms.Label();
      this.textBoxAppID = new System.Windows.Forms.TextBox();
      this.buttonSetAppID = new System.Windows.Forms.Button();
      this.buttonRegisterApp = new System.Windows.Forms.Button();
      this.listBoxLinks = new System.Windows.Forms.ListBox();
      this.label2 = new System.Windows.Forms.Label();
      this.label3 = new System.Windows.Forms.Label();
      this.textBoxAddNew = new System.Windows.Forms.TextBox();
      this.buttonAddNew = new System.Windows.Forms.Button();
      this.SuspendLayout();
      // 
      // label1
      // 
      this.label1.AutoSize = true;
      this.label1.Location = new System.Drawing.Point(13, 55);
      this.label1.Name = "label1";
      this.label1.Size = new System.Drawing.Size(40, 13);
      this.label1.TabIndex = 0;
      this.label1.Text = "AppID:";
      // 
      // textBoxAppID
      // 
      this.textBoxAppID.Location = new System.Drawing.Point(56, 52);
      this.textBoxAppID.Name = "textBoxAppID";
      this.textBoxAppID.Size = new System.Drawing.Size(203, 20);
      this.textBoxAppID.TabIndex = 1;
      // 
      // buttonSetAppID
      // 
      this.buttonSetAppID.Location = new System.Drawing.Point(276, 52);
      this.buttonSetAppID.Name = "buttonSetAppID";
      this.buttonSetAppID.Size = new System.Drawing.Size(75, 23);
      this.buttonSetAppID.TabIndex = 2;
      this.buttonSetAppID.Text = "Set AppID";
      this.buttonSetAppID.UseVisualStyleBackColor = true;
      this.buttonSetAppID.Click += new System.EventHandler(this.buttonSetAppID_Click);
      // 
      // buttonRegisterApp
      // 
      this.buttonRegisterApp.Location = new System.Drawing.Point(11, 13);
      this.buttonRegisterApp.Name = "buttonRegisterApp";
      this.buttonRegisterApp.Size = new System.Drawing.Size(101, 23);
      this.buttonRegisterApp.TabIndex = 3;
      this.buttonRegisterApp.Text = "Register the app";
      this.buttonRegisterApp.UseVisualStyleBackColor = true;
      this.buttonRegisterApp.Click += new System.EventHandler(this.buttonRegisterApp_Click);
      // 
      // listBoxLinks
      // 
      this.listBoxLinks.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
      this.listBoxLinks.FormattingEnabled = true;
      this.listBoxLinks.HorizontalScrollbar = true;
      this.listBoxLinks.Location = new System.Drawing.Point(9, 113);
      this.listBoxLinks.Name = "listBoxLinks";
      this.listBoxLinks.Size = new System.Drawing.Size(342, 238);
      this.listBoxLinks.TabIndex = 4;
      // 
      // label2
      // 
      this.label2.AutoSize = true;
      this.label2.Location = new System.Drawing.Point(10, 89);
      this.label2.Name = "label2";
      this.label2.Size = new System.Drawing.Size(57, 13);
      this.label2.TabIndex = 5;
      this.label2.Text = "Shell items";
      // 
      // label3
      // 
      this.label3.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
      this.label3.AutoSize = true;
      this.label3.Location = new System.Drawing.Point(11, 371);
      this.label3.Name = "label3";
      this.label3.Size = new System.Drawing.Size(29, 13);
      this.label3.TabIndex = 6;
      this.label3.Text = "Path";
      // 
      // textBoxAddNew
      // 
      this.textBoxAddNew.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
      this.textBoxAddNew.Location = new System.Drawing.Point(46, 368);
      this.textBoxAddNew.Name = "textBoxAddNew";
      this.textBoxAddNew.Size = new System.Drawing.Size(302, 20);
      this.textBoxAddNew.TabIndex = 7;
      // 
      // buttonAddNew
      // 
      this.buttonAddNew.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
      this.buttonAddNew.Location = new System.Drawing.Point(272, 397);
      this.buttonAddNew.Name = "buttonAddNew";
      this.buttonAddNew.Size = new System.Drawing.Size(75, 23);
      this.buttonAddNew.TabIndex = 8;
      this.buttonAddNew.Text = "Add new";
      this.buttonAddNew.UseVisualStyleBackColor = true;
      this.buttonAddNew.Click += new System.EventHandler(this.buttonAddNew_Click);
      // 
      // FormJumpList
      // 
      this.AcceptButton = this.buttonSetAppID;
      this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
      this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
      this.ClientSize = new System.Drawing.Size(360, 429);
      this.Controls.Add(this.buttonAddNew);
      this.Controls.Add(this.textBoxAddNew);
      this.Controls.Add(this.label3);
      this.Controls.Add(this.label2);
      this.Controls.Add(this.listBoxLinks);
      this.Controls.Add(this.buttonRegisterApp);
      this.Controls.Add(this.buttonSetAppID);
      this.Controls.Add(this.textBoxAppID);
      this.Controls.Add(this.label1);
      this.Name = "FormJumpList";
      this.Text = "CQAutomaticJumpListSampleCS";
      this.ResumeLayout(false);
      this.PerformLayout();

    }

    #endregion

    private System.Windows.Forms.Label label1;
    private System.Windows.Forms.TextBox textBoxAppID;
    private System.Windows.Forms.Button buttonSetAppID;
    private System.Windows.Forms.Button buttonRegisterApp;
    private System.Windows.Forms.ListBox listBoxLinks;
    private System.Windows.Forms.Label label2;
    private System.Windows.Forms.Label label3;
    private System.Windows.Forms.TextBox textBoxAddNew;
    private System.Windows.Forms.Button buttonAddNew;
  }
}

