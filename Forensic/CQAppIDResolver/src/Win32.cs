using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;

//additional
//https://github.com/winsiderss/systeminformer/blob/16c1ddf12154cfd75353ff4175d33b081c70cae9/phlib/include/appresolverp.h


namespace Cqure.Forensics.AutomaticDestinations
{
  //{ 0xDE25675A, 0x72DE, 0x44b4,{ 0x93, 0x73, 0x05, 0x17, 0x04, 0x50, 0xC1, 0x40 } };
  [ComImport, Guid("DE25675A-72DE-44b4-9373-05170450C140"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)] 
  interface IApplicationResolver62
  {
    //// IApplicationResolver62
    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 GetAppIDForShortcut([In] IShellItem psi, out IntPtr ppszAppID);
    //STDMETHOD(GetAppIDForShortcut)(THIS,
    //    _In_ IShellItem * psi,
    //    _Outptr_ PWSTR* ppszAppID
    //    ) PURE;

    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 GetAppIDForShortcutObject([In] IntPtr psl, IShellItem psi, out IntPtr ppszAppID);
    //STDMETHOD(GetAppIDForShortcutObject)(THIS,
    //    _In_ IShellLinkW * psl,
    //    _In_ IShellItem* psi,
    //    _Outptr_ PWSTR* ppszAppID
    //    ) PURE;

    //[MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    //UInt32 GetAppIDForWindow([In] UInt32 HWND, out IntPtr ppszAppID, out bool pfPinningPrevented, out bool pfExplicitAppID, out bool pfEmbeddedShortcutValid);
    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 GetAppIDForWindow([In] UInt32 HWND, [MarshalAs(UnmanagedType.LPWStr)] out string ppszAppID, out bool pfPinningPrevented, out bool pfExplicitAppID, out bool pfEmbeddedShortcutValid);
    //STDMETHOD(GetAppIDForWindow)(THIS,
    //    _In_ HWND hwnd,
    //    _Outptr_ PWSTR* ppszAppID,
    //    _Out_opt_ BOOL* pfPinningPrevented,
    //    _Out_opt_ BOOL* pfExplicitAppID,
    //    _Out_opt_ BOOL* pfEmbeddedShortcutValid
    //    ) PURE;

    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 GetAppIDForProcess([In] UInt32 dwProcessID, [MarshalAs(UnmanagedType.LPWStr)] out string ppszAppID, out bool pfPinningPrevented, out bool pfExplicitAppID, out bool pfEmbeddedShortcutValid);
    //[MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    //UInt32 GetAppIDForProcess([In] UInt64 dwProcessID, out IntPtr ppszAppID, object pfPinningPrevented, object pfExplicitAppID, object pfEmbeddedShortcutValid);
    //[MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    //UInt32 GetAppIDForProcess([In] UInt64 dwProcessID, out IntPtr ppszAppID, out IntPtr pfPinningPrevented, out IntPtr pfExplicitAppID, out IntPtr pfEmbeddedShortcutValid);
    //STDMETHOD(GetAppIDForProcess)(THIS,
    //    _In_ ULONG dwProcessID,
    //    _Outptr_ PWSTR* ppszAppID,
    //    _Out_opt_ BOOL* pfPinningPrevented,
    //    _Out_opt_ BOOL* pfExplicitAppID,
    //    _Out_opt_ BOOL* pfEmbeddedShortcutValid
    //    ) PURE;

    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 GetShortcutForProcess([In] UInt64 dwProcessID, out IShellItem ppsi);
    //STDMETHOD(GetShortcutForProcess)(THIS,
    //    _In_ ULONG dwProcessID,
    //    _Outptr_ IShellItem** ppsi
    //    ) PURE;

    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 GetBestShortcutForAppID([In] string pszAppID, out IShellItem ppsi);
    //STDMETHOD(GetBestShortcutForAppID)(THIS,
    //    _In_ PCWSTR pszAppID,
    //    _Outptr_ IShellItem** ppsi
    //    ) PURE;

    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 GetBestShortcutAndAppIDForAppPath([In] string pszAppPath, out IShellItem ppsi, out IntPtr ppszAppID);
    //STDMETHOD(GetBestShortcutAndAppIDForAppPath)(THIS,
    //    _In_ PCWSTR pszAppPath,
    //    _Outptr_opt_ IShellItem** ppsi,
    //    _Outptr_opt_ PWSTR* ppszAppID
    //    ) PURE;

    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 CanPinApp([In] IShellItem psi);
    //STDMETHOD(CanPinApp)(THIS,
    //    _In_ IShellItem * psi
    //    ) PURE;

    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 CanPinAppShortcut([In] IntPtr psl, [In] IShellItem psi);
    //STDMETHOD(CanPinAppShortcut)(THIS,
    //    _In_ IShellLinkW * psl,
    //    _In_ IShellItem* psi
    //    ) PURE;

    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 GetRelaunchProperties([In] UInt32 hwnd, out IntPtr ppszAppID, out IntPtr ppszCmdLine, out IntPtr ppszIconResource, out IntPtr ppszDisplayNameResource);
    //STDMETHOD(GetRelaunchProperties)(THIS,
    //    _In_ HWND hwnd,
    //    _Outptr_opt_result_maybenull_ PWSTR* ppszAppID,
    //    _Outptr_opt_result_maybenull_ PWSTR* ppszCmdLine,
    //    _Outptr_opt_result_maybenull_ PWSTR* ppszIconResource,
    //    _Outptr_opt_result_maybenull_ PWSTR* ppszDisplayNameResource,
    //    _Out_opt_ BOOL* pfPinnable
    //    ) PURE;

    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 GenerateShortcutFromWindowProperties([In] UInt32 hwnd, out IShellItem ppsi);
    //STDMETHOD(GenerateShortcutFromWindowProperties)(THIS,
    //    _In_ HWND hwnd,
    //    _Outptr_ IShellItem** ppsi
    //    ) PURE;

    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 GenerateShortcutFromItemProperties([In] IShellItem2 psi2, out IShellItem ppsi);
    //STDMETHOD(GenerateShortcutFromItemProperties)(THIS,
    //    _In_ IShellItem2 * psi2,
    //    _Out_opt_ IShellItem** ppsi
    //    ) PURE;
    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 GetLauncherAppIDForItem();
    //// STDMETHOD(GetLauncherAppIDForItem)(THIS)

    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 GetShortcutForAppID();
    //// STDMETHOD(GetShortcutForAppID)(THIS)
    [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
    UInt32 GetLauncherAppIDForItemEx();
    //// STDMETHOD(GetLauncherAppIDForItemEx)(THIS)

  }

  [ComImport, Guid("660B90C8-73A9-4B58-8CAE-355B7F55341B")]
  class StartMenuCacheAndAppResolver
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

    public static string GetAppIDForProcessId(UInt64 processId)
    {
      IntPtr appid = IntPtr.Zero;
      var appResolver = new StartMenuCacheAndAppResolver();
      var appResolverInt = (IApplicationResolver62)appResolver;
      IntPtr a = IntPtr.Zero;

      bool b1, b2, b3;
      string s = string.Empty;
      UInt32 hr = appResolverInt.GetAppIDForProcess((uint)processId, out s, out b1, out b2, out b3);
      return s;
    }

    internal static string GetAppIDForWindowId(uint window)
    {
      IntPtr appid = IntPtr.Zero;
      var appResolver = new StartMenuCacheAndAppResolver();
      var appResolverInt = (IApplicationResolver62)appResolver;
      IntPtr a = IntPtr.Zero;

      IntPtr ib1 = IntPtr.Zero;
      IntPtr ib2 = IntPtr.Zero;
      IntPtr ib3 = IntPtr.Zero;
      bool b1, b2, b3;
      string s = string.Empty;
      UInt32 hr = appResolverInt.GetAppIDForWindow(window, out s, out b1, out b2, out b3);
      return s;
    }
     
  }

}
