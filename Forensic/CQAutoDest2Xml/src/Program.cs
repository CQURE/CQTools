using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Xsl;

//using Cqure.Forensics.MSSHLLINK;
using Cqure.Forensics.MSCFB;
using Cqure.Forensics.AutomaticDestinations;

using NDesk.Options;

namespace Cqure.Forensics.AutomaticDestinations
{
  class AutoDest2Xml
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

      AutoDest2Xml p = new AutoDest2Xml();
      p.Resolve();

      string outDir = arguments.OutDir;
      string inDir = arguments.Dir;
      string xslFile = arguments.Xsl;

      try
      {
        string temp = string.Empty;
        XmlDocument xmlDoc = new XmlDocument();
        XmlElement tempElement = null;

        tempElement = xmlDoc.CreateElement("autoFiles");
        var root = xmlDoc.AppendChild(tempElement);

        if (!Directory.Exists(arguments.OutDir))
        {
          string o = Path.GetFullPath(arguments.OutDir);
          Directory.CreateDirectory(o);
        }

        foreach (var file in Directory.GetFiles(inDir, "*.automaticDestinations-ms"))
        {
          string outName = Path.GetFileNameWithoutExtension(file);
          temp = Path.Combine(outDir, outName + ".xml");
          try
          {
            if (p.Convert2Xml(file, temp))
            {
              tempElement = xmlDoc.CreateElement("autoFile");
              tempElement.SetAttribute("file", outName + ".xml");
              tempElement.SetAttribute("appid", outName);
              root.AppendChild(tempElement);
            }
          }
          catch (Exception ex){ Console.WriteLine($"Problem with {file}, ex: {ex.Message}"); }
        }
        string masterFile = Path.Combine(outDir, "master.xml");
        xmlDoc.Save(masterFile);
        string htmlFile = Path.Combine(outDir, "report.html");
        p.TransformXsl(masterFile, htmlFile, xslFile);
      }
      catch(Exception ex)
      {
        Console.WriteLine($"Something went wrong: {ex.Message}");
      }
    }

    public bool Convert2Xml(string fileName, string destFile)
    {
      AutomaticDestinationsFile autoFile = AutomaticDestinationsFile.Load(fileName);
      if (autoFile.DestList == null || autoFile.CFBLNKEntries == null || autoFile.CFBLNKEntries.Count == 0)
        return false;

      string outName = Path.GetFileNameWithoutExtension(fileName);

      //string destFile = $"{outDir}";
      autoFile.SaveAsXml(destFile);
      return true;
    }

    public void Resolve()
    {
      AppDomain.CurrentDomain.AssemblyResolve += (sender, args) =>
      {
        string resourceName = new AssemblyName(args.Name).Name + ".dll";
        string resource = Array.Find(this.GetType().Assembly.GetManifestResourceNames(), element => element.EndsWith(resourceName));

        using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resource))
        {
          Byte[] assemblyData = new Byte[stream.Length];
          stream.Read(assemblyData, 0, assemblyData.Length);
          return Assembly.Load(assemblyData);
        }
      };
    }

    public void TransformXsl(string xmlFile, string htmlFile, string xslFile = null)
    {
      // Create the XsltSettings object with script enabled.
      XsltSettings settings = new XsltSettings(true, true);

      XslCompiledTransform xslt = new XslCompiledTransform();

      try
      {
        if(!string.IsNullOrEmpty(xslFile))
          xslt.Load(xslFile, settings, new XmlUrlResolver());
        else
        {
          string xslResourceName = "autoDest.xsl";
          string xslResource = Array.Find(this.GetType().Assembly.GetManifestResourceNames(), element => element.EndsWith(xslResourceName));
          using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(xslResource))
          {
            using (XmlReader xmlReader = XmlReader.Create(stream))
            {
              //xmlReader.ReadToDescendant("xsl:stylesheet");
              xslt.Load(xmlReader, settings, new XmlUrlResolver());
            }
          }
        }
        xslt.Transform(xmlFile, htmlFile);
      }
      catch (Exception ex)
      {
        Console.WriteLine($"Something went wrong: {ex.Message}");
      }

    }


  }
  public class CommandLineArguments
  {
    private OptionSet options;

    public CommandLineArguments()
    {
      this.options = new OptionSet() {
        { "in=|indir=|dir=|d=", @"Path to the directory containing automaticDestinations-ms files, most probably %APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations", x => this.Dir = x },
        { "out=|outdir=|o=", @"Path to the output directory", x => this.OutDir = x },
        { "xsl=|inxsl=", @"Optional xsl template", x => this.Xsl = x },
        { "outxsl=", @"Dump default xsl template to file", x => this.OutXsl = x },
      };
    }

    public string Dir { get; set; }
    public string OutDir { get; set; }
    public string Xsl { get; set; }
    public string OutXsl { get; set; }
    public bool Help { get; set; }
    public bool Debug { get; set; }

    public void Parse(string[] args)
    {
      List<string> addr = this.options.Parse(args);

      if (string.IsNullOrEmpty(Dir) || string.IsNullOrEmpty(OutDir))
      {
        Console.WriteLine("You need to specify required parameteres");
        this.Help = true;
      }

      if (!string.IsNullOrEmpty(OutXsl))
      {
        saveXslt(OutXsl);
        Console.WriteLine($"Default xslt template successfully written to the {OutXsl} file");
      }
    }

    private void saveXslt(string outXSLFile)
    {
      string xslResourceName = "autoDest.xsl";
      string xslResource = Array.Find(this.GetType().Assembly.GetManifestResourceNames(), element => element.EndsWith(xslResourceName));
      using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(xslResource))
      {
        byte[] data = new byte[stream.Length];
        stream.Read(data, 0, data.Length);
        File.WriteAllBytes(outXSLFile, data);
      }
    }
    public void ShowHelp()
    {
      Console.WriteLine("{0}, ver. {1}, by Michal Grzegorzewski, mgrzeg@cqure.pl", System.Diagnostics.Process.GetCurrentProcess().ProcessName, Utils.GetVersion());
      Console.WriteLine();
      Console.WriteLine("This tool allows you to extract information from your automatic destinations files");
      Console.WriteLine(@"Usage: {0} /dir /outdir", System.Diagnostics.Process.GetCurrentProcess().ProcessName);
      Console.WriteLine("Available parameters:");
      this.options.WriteOptionDescriptions(Console.Out);
      Console.WriteLine();
      Console.WriteLine("Credits");
      Console.WriteLine("Argument parsing by NDesk.Options.");
    }
  }


}
