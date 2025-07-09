using System;
using System.Collections.Generic;
using System.IO;
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

      string app = AppIDCalculator.Analyze(arguments.File);
    }
  }

  public class CommandLineArguments
  {
    private OptionSet options;

    public CommandLineArguments()
    {
      this.options = new OptionSet() {
        { "file=|f=", "Path to the .exe file", x => this.File = x },
      };
    }

    public string File { get; set; }
    public bool Help { get; set; }
    public bool Debug { get; set; }

    public void Parse(string[] args)
    {
      List<string> addr = this.options.Parse(args);

      if(string.IsNullOrEmpty(File))
      {
        Console.WriteLine("You need to specify the AppID of the process window, or path to the .exe file");
        this.Help = true;
      }

    }

    public void ShowHelp()
    {
      Console.OutputEncoding = Encoding.UTF8;
      Console.WriteLine("{0}, ver. {1}", System.Diagnostics.Process.GetCurrentProcess().ProcessName, Utils.GetVersion());
      Console.WriteLine("Development & Ideas by Michal Grzegorzewski (mgrzeg@cqure.pl) & Paula Januszkiewicz (paula@cqure.pl)", System.Diagnostics.Process.GetCurrentProcess().ProcessName, Utils.GetVersion());
      Console.WriteLine("Copyright © CQURE"); 
      Console.WriteLine();
      Console.WriteLine("This tool allows you to calculate the name of the jumplist file from provided AppID.");
      Console.WriteLine(@"Usage: {0} /file", System.Diagnostics.Process.GetCurrentProcess().ProcessName);
      Console.WriteLine("Available parameters:");
      this.options.WriteOptionDescriptions(Console.Out);
      Console.WriteLine();
      Console.WriteLine("Credits");
      Console.WriteLine("Code based on the https://www.hexacorn.com/tools/appid_calc.pl by Hexacorn");
      Console.WriteLine("More information: http://www.hexacorn.com/blog/2013/04/30/jumplists-file-names-and-appid-calculator/");
      Console.WriteLine("Argument parsing by NDesk.Options.");
    }
  }

}
