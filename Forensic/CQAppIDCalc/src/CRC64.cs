using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cqure.Forensics.AutomaticDestinations
{
  public class CRC64
  {
    private const ulong POLY64 = 0x92C64265D32139A4;
    private static ulong[] CRC64Table = null;
    private static void initCRC64Table()
    {
      if(CRC64Table == null)
      {
        CRC64Table = new ulong[256];
        for (ulong i = 0; i < 256; i++)
        {
          ulong lv = i;
          for (ulong j = 0; j < 8; j++)
          {
            ulong fl = lv & 1;
            lv = lv >> 1;
            lv = (fl == 1) ? lv ^ POLY64 : lv;
            CRC64Table[i] = lv;
          }
        }
      }

      //for (int i = 0; i < 256; i++)
      //{
      //  //Console.WriteLine($"CRC[{i}]: {Crc64TableNew[i]}");
      //  Console.WriteLine($"{Crc64TableNew[i]}");
      //}
    }

    public static ulong CalculateCRC64(string text)
    {
      text = text.ToUpperInvariant();
      ulong crc = 0xFFFFFFFFFFFFFFFF;

      initCRC64Table();

      for (int i = 0; i < text.Length; i++)
      {
        ulong u = (ulong)text[i];
        crc = (crc >> 8) ^ CRC64Table[(crc ^ u) & 0xff];
        crc = (crc >> 8) ^ CRC64Table[(crc ^ 0) & 0xff];
      }

      return crc;
    }
  }
}
