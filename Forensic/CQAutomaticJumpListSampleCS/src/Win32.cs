using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;

//additional
//https://github.com/oysteinkrog/WPF-Shell-Integration-Library/blob/master/Microsoft.Windows.Shell/Standard/ShellProvider.cs


namespace Cqure.Forensics.AutomaticDestinations
{

  //[ComImport, Guid("86c14003-4d6b-4ef3-a7b4-0506663b2e68"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  [ComImport, Guid("12337d35-94c6-48a0-bce7-6a9c69d4d600"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  interface IApplicationDestinations
  {
    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 SetAppID([In] [MarshalAs(UnmanagedType.LPWStr)] string pszAppID);
    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 RemoveDestination(IntPtr punk);
    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 RemoveAllDestinations();
  }

  [ComImport, Guid("86c14003-4d6b-4ef3-a7b4-0506663b2e68")]
  class ApplicationDestinations
  {
  }

  internal enum APPDOCLISTTYPE
  {
    ADLT_RECENT = 0,   // The recently used documents list
    ADLT_FREQUENT,     // The frequently used documents list
  }

  [ComImport, Guid("92CA9DCD-5622-4BBA-A805-5E9F541BD8C9"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  interface IObjectArray
  {
    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 GetCount(ref UInt32 pcObjects);

    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 GetAt([In] uint uiIndex, [In] ref Guid riid, out IntPtr ppv);
  }


  //internal interface IObjectArray
  //{
  //  uint GetCount();
  //  [return: MarshalAs(UnmanagedType.IUnknown)]
  //  object GetAt([In] uint uiIndex, [In] ref Guid riid);
  //}

  [ComImport, Guid("92CA9DCD-5622-4bba-A805-5E9F541BD8C9"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  interface IObjectCollection : IObjectArray
  {
    #region IObjectArray redeclarations
    new uint GetCount();
    [return: MarshalAs(UnmanagedType.IUnknown)]
    new object GetAt([In] uint uiIndex, [In] ref Guid riid);
    #endregion

    void AddObject([MarshalAs(UnmanagedType.IUnknown)] object punk);
    void AddFromArray(IObjectArray poaSource);
    void RemoveObjectAt(uint uiIndex);
    void Clear();
  }

  [ComImport, Guid("3c594f9f-9f30-47a1-979a-c9e83d3d0a06"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  interface IApplicationDocumentLists
  {
    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 SetAppID([MarshalAs(UnmanagedType.LPWStr)] string pszAppID);

    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 GetList([In] APPDOCLISTTYPE listtype, [In] uint cItemsDesired, [In] ref Guid riid, out IObjectArray ppv);
  }

  [ComImport, Guid("86BEC222-30F2-47E0-9F25-60D11CD75C28")]
  class ApplicationDocumentLists
  {
  }


  enum GETPROPERTYSTOREFLAGS
  {
    GPS_DEFAULT = 0,
    GPS_HANDLERPROPERTIESONLY = 0x1,
    GPS_READWRITE = 0x2,
    GPS_TEMPORARY = 0x4,
    GPS_FASTPROPERTIESONLY = 0x8,
    GPS_OPENSLOWITEM = 0x10,
    GPS_DELAYCREATION = 0x20,
    GPS_BESTEFFORT = 0x40,
    GPS_NO_OPLOCK = 0x80,
    GPS_PREFERQUERYPROPERTIES = 0x100,
    GPS_EXTRINSICPROPERTIES = 0x200,
    GPS_EXTRINSICPROPERTIESONLY = 0x400,
    GPS_MASK_VALID = 0x7ff
  };

  enum SIGDN : UInt32
  {
    SIGDN_NORMALDISPLAY = 0,
    SIGDN_PARENTRELATIVEPARSING = 0x80018001,
    SIGDN_DESKTOPABSOLUTEPARSING = 0x80028000,
    SIGDN_PARENTRELATIVEEDITING = 0x80031001,
    SIGDN_DESKTOPABSOLUTEEDITING = 0x8004c000,
    SIGDN_FILESYSPATH = 0x80058000,
    SIGDN_URL = 0x80068000,
    SIGDN_PARENTRELATIVEFORADDRESSBAR = 0x8007c001,
    SIGDN_PARENTRELATIVE = 0x80080001,
    SIGDN_PARENTRELATIVEFORUI = 0x80094001
  };

  [ComImport, Guid("43826d1e-e718-42ee-bc55-a1e261c37bfe"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  interface IShellItem
  {
    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 BindToHandler(IntPtr pbc, ref Guid bhid, ref Guid riid, out IntPtr ppv);

    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 GetParent(out IShellItem ppsi);

    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 GetDisplayName(SIGDN sigdnName, out IntPtr ppszName);

    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 GetAttributes(UInt64 sfgaoMask, out UInt64 psfgaoAttribs);

    UInt32 Compare(IShellItem psi, UInt32 hint, out int piOrder);

  }


  [ComImport, Guid("7e9fb0d3-919f-4307-ab2e-9b1860310c93"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  interface IShellItem2 : IShellItem
  {
    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32  GetPropertyStore(GETPROPERTYSTOREFLAGS flags,ref Guid riid, IntPtr ppv);

    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 GetPropertyStoreWithCreateObject(GETPROPERTYSTOREFLAGS flags, IntPtr punkCreateObject, ref Guid riid, [Out] IntPtr ppv);

    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 GetPropertyStoreForKeys(IntPtr rgKeys, UInt32 cKeys, GETPROPERTYSTOREFLAGS flags, ref Guid riid,[Out] IntPtr ppv);

    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 GetPropertyDescriptionList(IntPtr keyType, ref Guid riid, [Out] IntPtr ppv);

    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 Update(IntPtr pbc);

    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 GetProperty(IntPtr key, out IntPtr ppropvar);

    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 GetCLSID(IntPtr key, out Guid pclsid);

    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 GetFileTime(IntPtr key, System.Runtime.InteropServices.ComTypes.FILETIME pft);

    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 GetInt32(IntPtr key, out int pi);

    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 GetString(IntPtr key, out string ppsz);

    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 GetUInt32(IntPtr key, out UInt32 pui);

    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 GetUInt64(IntPtr key, out UInt64 pull);

    UInt32 GetBool(IntPtr key, out bool pf);
  }




  public static class Win32
  {
    [DllImport("shell32.dll", SetLastError = true)]
    public static extern UInt32 SetCurrentProcessExplicitAppUserModelID([MarshalAs(UnmanagedType.LPWStr)]string AppId);

    //[DllImport("shell32.dll", SetLastError = true)]
    //public static extern UInt32 GetCurrentProcessExplicitAppUserModelID(ref IntPtr AppId);

    //[DllImport("ole32.dll", SetLastError = true)]
    //public static extern void CoTaskMemFree(IntPtr ptr);


    public enum ShellAddToRecentDocsFlags
    {
      Pidl = 0x001,
      Path = 0x002,
      PathW = 0x003,
    }

    [DllImport("shell32.dll", CharSet = CharSet.Ansi)]
    public static extern void SHAddToRecentDocs(ShellAddToRecentDocsFlags flag, string path);

    //[DllImport("shell32.dll")]
    //public static extern void SHAddToRecentDocs(ShellAddToRecentDocsFlags flag, IntPtr pidl);

    public static void AddToRecentDocs(string path)
    {
      int err = 0;
      err = Marshal.GetLastWin32Error();
      SHAddToRecentDocs(ShellAddToRecentDocsFlags.Path, path);
      err = Marshal.GetLastWin32Error();
    }

    public static List<string> GetDocsList(string appID)
    {
      var applicationDocsList = new ApplicationDocumentLists();
      var applicationDocsListInt = (IApplicationDocumentLists)applicationDocsList;
      uint ret = applicationDocsListInt.SetAppID(appID);

      IObjectArray objectArray = null;
      //IntPtr intPtr = Marshal.AllocHGlobal(0x10000);
      Guid g = new Guid("92CA9DCD-5622-4BBA-A805-5E9F541BD8C9");
      object o;
      List<string> links = null;
      //Guid g = new Guid("5632b1a4-e38a-400a-928a-d4cd63230295");
      //var obj = applicationDocsListInt.GetList(APPDOCLISTTYPE.ADLT_RECENT, 0, g);
      var ret1 = applicationDocsListInt.GetList(APPDOCLISTTYPE.ADLT_RECENT, 0, ref g, out objectArray);
      if(ret1 == 0)
      {
        links = fromComCollection(objectArray);
      }
      //var ret1 = applicationDocsListInt.GetList(APPDOCLISTTYPE.ADLT_RECENT, 99, g, ref objectArray);
      //Win32.GetDocsList();
      return links;
    }

    static List<string> fromComCollection(IObjectArray array)
    {
      uint count = 0;
      uint hr = array.GetCount(ref count);
      Guid IID_Unknown = new Guid("00000000-0000-0000-C000-000000000046");
      List<string> links = new List<string>();

      for(uint i = 0; i < count; i++)
      {
        IntPtr collectionItem = IntPtr.Zero;

        hr = array.GetAt(i, ref IID_Unknown, out collectionItem);
        var shellItem = (IShellItem2) Marshal.GetObjectForIUnknown(collectionItem);
        string s = fromIShellItem(shellItem);
        if (!string.IsNullOrEmpty(s))
          links.Add(s);
      }

      return links;
    }

    static string fromIShellItem(IShellItem2 shellItem)
    {
      string str = string.Empty;
      IntPtr outStr = IntPtr.Zero;
      try
      {
        shellItem.GetDisplayName(SIGDN.SIGDN_FILESYSPATH, out outStr);
        str = Marshal.PtrToStringAuto(outStr);
        Marshal.FreeCoTaskMem(outStr);
      }
      catch (Exception cex)
      {
        Console.WriteLine(cex.Message);
      }
      if (outStr != IntPtr.Zero)
      {
      }
      return str;
    }

  }

}
