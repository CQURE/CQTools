using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

namespace Cqure.Forensics.AutomaticDestinations
{

  public partial class FormJumpList : Form
  {
    string AppID = string.Empty;
    public FormJumpList()
    {
      InitializeComponent();

      //string appid = "CQTestConsole";
      //string appid = "MSEdge";
      //string appid = "CQTestWinForm";
      AppID = "CQTestWinForm";

      if (Program.CMD != null && Program.CMD.Length == 1)
      {
        AppID = Program.CMD[0];
      }

      textBoxAppID.Text = AppID;
      //RegisterApp();
      Run();//AppID);
    }

    private void buttonSetAppID_Click(object sender, EventArgs e)
    {
      if(!string.IsNullOrEmpty(textBoxAppID.Text))
      {
        UInt32 ret = 0;
        int error = Marshal.GetLastWin32Error();
        ret = Win32.SetCurrentProcessExplicitAppUserModelID(textBoxAppID.Text);
        AppID = textBoxAppID.Text;
        //if(ret != 0)
        {
          error = Marshal.GetLastWin32Error();
        }
        GetList();// textBoxAppID.Text);
      }
    }

    public void Run()// string appID)
    {
      uint ret = 0;// Win32.SetCurrentProcessExplicitAppUserModelID("CQTestConsole");
      ret = Win32.SetCurrentProcessExplicitAppUserModelID(AppID);
      //GetList();
    }

    private void GetList()//string appID)
    {
      List<string> links = Win32.GetDocsList(AppID);
      listBoxLinks.Items.Clear();
      listBoxLinks.Items.AddRange(links.ToArray());
    }

    public static void ClearHistory()
    {
      var applicationDestinations = new ApplicationDestinations();
      var applicationDestinationsInt = (IApplicationDestinations)applicationDestinations;
      applicationDestinationsInt.RemoveAllDestinations();
    }

    //public static void ClearHistory1()
    //{
    //  Guid CLSID_ApplicationDestinations = new Guid("86c14003-4d6b-4ef3-a7b4-0506663b2e68");
    //  //Guid CLSID_ApplicationDestinations = new Guid("12337D35-94C6-48A0-BCE7-6A9C69D4D600");
    //  //Guid CLSID_ApplicationDestinations = new Guid("95E15D0A-66E6-93D9-C53C-76E6219D3341");
    //  Type shellDesktopType = Type.GetTypeFromCLSID(CLSID_ApplicationDestinations);//, "REMOTESERVER", true);
    //  //IApplicationDestinations pad = (IApplicationDestinations)Activator.CreateInstance(shellDesktopType);
    //  object pad = Activator.CreateInstance(shellDesktopType);
    //  shellDesktopType.InvokeMember("RemoveAllDestinations", System.Reflection.BindingFlags.InvokeMethod, null, pad, null);
    //  //pad.RemoveAllDestinations();

    //}

    public static void RegisterApp()
    {
      string appName = "AppIDWinForm";
      string friendlyAppName = "CQURE AppID Tester";
      string progID = $"CQURE.AutomaticDestinations.{appName}";
      string classesTxtKey = @"HKEY_CURRENT_USER\SOFTWARE\Classes\.txt\OpenWithProgids";
      string classesAppKey = $@"HKEY_CURRENT_USER\SOFTWARE\Classes\{progID}";
      string curVerKey = $@"{classesAppKey}\CurVer";
      string defaultIconKey = $@"{classesAppKey}\DefaultIcon";
      string shellKey = $@"{classesAppKey}\shell";
      string shellOpenCommandKey = $@"{classesAppKey}\shell\Open\Command";
      string binPath = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;

      Registry.SetValue(classesTxtKey, progID, new byte[0], RegistryValueKind.None);
      Registry.SetValue(classesAppKey, "FriendlyTypeName", friendlyAppName);
      Registry.SetValue(curVerKey, "", progID);
      Registry.SetValue(defaultIconKey, "", binPath);
      Registry.SetValue(shellKey, "", "Open");
      Registry.SetValue(shellOpenCommandKey, "", $"{binPath} %1");
    }

    private void buttonRegisterApp_Click(object sender, EventArgs e)
    {
      RegisterApp();
    }

    private void buttonAddNew_Click(object sender, EventArgs e)
    {
      AddNewEntry(textBoxAddNew.Text);
    }

    private void AddNewEntry(string text)
    {
      if(!string.IsNullOrEmpty(text) && text.EndsWith(".txt", StringComparison.CurrentCultureIgnoreCase) && System.IO.File.Exists(text))
        Win32.AddToRecentDocs(text);
      GetList();
    }
  }
}

