using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace Cqure.Forensics.AutomaticDestinations
{
  internal class Utils
  {
    public static string GetVersion()
    {
      Assembly assem = Assembly.GetEntryAssembly();
      AssemblyName assemName = assem.GetName();
      Version ver = assemName.Version;
      return ver.ToString();
    }

    public static byte[] reverse(byte[] data)
    {
      return reverse(data, 0);
    }
    public static byte[] reverse(byte[] data, int offset)
    {
      if (data == null || data.Length == 0 || offset > data.Length) return null;
      byte[] reversed = new byte[data.Length - offset];
      for (int i = 0; i < data.Length - offset; i++)
      {
        reversed[i] = data[data.Length - i - 1];
      }
      return reversed;
    }

    internal static byte[] fromString(string str)
    {
      string tempByteStr = string.Empty;
      byte tempByte = 0;
      List<byte> arr = new List<byte>();
      for (int i = 0; i < str.Length; i += 2)
      {
        tempByteStr = str.Substring(i, 2);
        byte.TryParse(tempByteStr, System.Globalization.NumberStyles.HexNumber | System.Globalization.NumberStyles.AllowHexSpecifier, System.Globalization.CultureInfo.InvariantCulture, out tempByte);
        arr.Add(tempByte);
      }
      return arr.ToArray();
    }

    internal static string prettyPrint(byte[] data)
    {
      int rowLength = 16;
      if (data == null) return string.Empty;
      //List<byte[]> byteRows = new List<byte[]>();

      byte[] rowByte = new byte[rowLength];

      StringBuilder sb = new StringBuilder();

      for (int i = 0; i < data.Length; i += rowLength)
      {
        if (data.Length - i > rowLength)
        {
          rowByte = new byte[rowLength];
          Array.Copy(data, i, rowByte, 0, rowLength);
          sb.Append(prettyPrintOneRow(rowByte, rowLength));
        }
        else
        {
          rowByte = new byte[data.Length - i];
          Array.Copy(data, i, rowByte, 0, rowByte.Length);
          sb.Append(prettyPrintOneRow(rowByte, rowLength));
        }
      }
      return sb.ToString();
    }

    static string prettyPrintOneRow(byte[] row, int rowLength)
    {
      string formattedLine = string.Empty;
      string digits = BitConverter.ToString(row).Replace('-', ' ');
      StringBuilder charsSB = new StringBuilder();

      for (int i = 0; i < row.Length; i++)
      {
        //if (char.IsLetterOrDigit((char)row[i]) || char.IsSymbol((char)row[i]))
        if (row[i] > 32 && row[i] < 254 && row[i] != 127)
        {
          charsSB.Append((char)row[i]);
        }
        else
          charsSB.Append('.');
      }
      string fmt = string.Format("{{0,-{0}}}{{1}}\r\n", (rowLength * 2 + rowLength - 1 + 3));
      formattedLine = string.Format(fmt, digits, charsSB.ToString());
      //Console.WriteLine(fmt, digits, charsSB.ToString());
      return formattedLine;
    }
  }
}
