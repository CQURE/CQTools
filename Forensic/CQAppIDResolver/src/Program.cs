using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using NDesk.Options;

namespace Cqure.Forensics.AutomaticDestinations
{
  class Program
  {
    static void Main(string[] args)
    {
      CommandLineArguments arguments = new CommandLineArguments();
      arguments.Parse(args);

      if (arguments.Help)
      {
        arguments.ShowHelp();
        return;
      }

      UInt32 pid = 0;
      if (!string.IsNullOrEmpty(arguments.PID))
      {
        if (arguments.PID.StartsWith("0x", StringComparison.CurrentCultureIgnoreCase))
          UInt32.TryParse(arguments.PID.Substring(2), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.CurrentCulture, out pid);
        else
          UInt32.TryParse(arguments.PID, out pid);
      }

      if(pid != 0)
      {
        try
        {
          string str = Win32.GetAppIDForProcessId(pid);
          Console.WriteLine(str);
        }
        catch (Exception ex) { Console.WriteLine($"Problem getting AppID: {ex.Message}"); }
      }

      UInt32 window = 0;
      if (!string.IsNullOrEmpty(arguments.Window))
      {
        if (arguments.Window.StartsWith("0x", StringComparison.CurrentCultureIgnoreCase))
          UInt32.TryParse(arguments.Window.Substring(2), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.CurrentCulture, out window);
        else
          UInt32.TryParse(arguments.Window, out window);
      }

      if (window != 0)
      {
        try
        {
          string str = Win32.GetAppIDForWindowId(window);
          Console.WriteLine(str);
        }
        catch (Exception ex) { Console.WriteLine($"Problem getting AppID: {ex.Message}"); }
      }


      if (arguments.All)
      {
        var processes = System.Diagnostics.Process.GetProcesses();
        foreach (var proc in processes)
        {
          try
          {
            Console.Write($"{proc.ProcessName}({proc.Id}):");
            string str = Win32.GetAppIDForProcessId((UInt32)proc.Id);
            Console.Write($"{str}");
          }
          catch (Exception ex) { Console.Write($"{ex.Message}"); }
          finally { Console.WriteLine(); }
        }
      }
    }
  }

  public class CommandLineArguments
  {
    private OptionSet options;

    public CommandLineArguments()
    {
      this.options = new OptionSet() {
        { "pid=|p=", "PID of the process", x => this.PID = x },
        { "window=|w=", "ID of window", x => this.Window = x },
        { "all|a", "Get all AppIDs for running processes", x => this.All = true },
      };
    }

    public bool All { get; set; }
    public string PID { get; set; }
    public string Window { get; set; }
    public bool Help { get; set; }
    public bool Debug { get; set; }

    public void Parse(string[] args)
    {
      List<string> addr = this.options.Parse(args);

      if (string.IsNullOrEmpty(PID) && string.IsNullOrEmpty(Window) && !All)
      {
        Console.WriteLine("You need to specify the PID of the process or ID of the window. You can also use -all to get data for all processess");
        this.Help = true;
      }

    }

    public void ShowHelp()
    {
      Console.WriteLine("{0}, ver. {1}", System.Diagnostics.Process.GetCurrentProcess().ProcessName, Utils.GetVersion());
      Console.WriteLine("Development & Ideas by Michal Grzegorzewski (mgrzeg@cqure.pl) & Paula Januszkiewicz (paula@cqure.pl)", System.Diagnostics.Process.GetCurrentProcess().ProcessName, Utils.GetVersion());
      Console.WriteLine("Copyright © CQURE");
      Console.WriteLine();
      Console.WriteLine("This tool allows you to find the AppID of the process or window. It uses undocumented COM interfaces provided by appresolver.dll");
      Console.WriteLine(@"Usage: {0} /pid /window", System.Diagnostics.Process.GetCurrentProcess().ProcessName);
      Console.WriteLine("Available parameters:");
      this.options.WriteOptionDescriptions(Console.Out);
      Console.WriteLine();
      Console.WriteLine("Credits");
      Console.WriteLine("Argument parsing by NDesk.Options.");
    }
  }

}
