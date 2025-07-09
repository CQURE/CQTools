using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Cqure.Forensics.AutomaticDestinations
{
  static class Program
  {
    /// <summary>
    /// The main entry point for the application.
    /// </summary>
    [STAThread]
    static void Main(string[] args)
    {
      if (args?.Length > 0)
      {
        string text = $"{args.Length}, {string.Concat(args)}";
        CMD = args;
      }
      //Win32.SetCurrentProcessExplicitAppUserModelID("CQTest");
      Application.EnableVisualStyles();
      Application.SetCompatibleTextRenderingDefault(false);
      Application.Run(new FormJumpList());
    }

    public static string[] CMD;
  }
}
