using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Xml;
using System.Collections.Specialized;
using System.Text.RegularExpressions;
using System.Net.NetworkInformation;
namespace DragonVisionLibrary
{
  public static class ExtensionMethod
{
    #region VietnameseSigns
    private static readonly string[] VietnameseSigns = new string[]
        {

            "aAeEoOuUiIdDyY",

            "áàạảãâấầậẩẫăắằặẳẵ",

            "ÁÀẠẢÃÂẤẦẬẨẪĂẮẰẶẲẴ",

            "éèẹẻẽêếềệểễ",

            "ÉÈẸẺẼÊẾỀỆỂỄ",

            "óòọỏõôốồộổỗơớờợởỡ",

            "ÓÒỌỎÕÔỐỒỘỔỖƠỚỜỢỞỠ",

            "úùụủũưứừựửữ",

            "ÚÙỤỦŨƯỨỪỰỬỮ",

            "íìịỉĩ",

            "ÍÌỊỈĨ",

            "đ",

            "Đ",

            "ýỳỵỷỹ",

            "ÝỲỴỶỸ"

        };


    /// <summary>
    /// Remove Sign Vietnamese String
    /// </summary>
    /// <param name="str"> string</param>
    /// <returns> string </returns>
    public static string RemoveSignVietnameseString(this string str)
    {
        try
        {
            for (int i = 1; i < VietnameseSigns.Length; i++)
            {
                for (int j = 0; j < VietnameseSigns[i].Length; j++)
                    str = str.Replace(VietnameseSigns[i][j], VietnameseSigns[0][i - 1]);
            }
            return str;
        }
        catch (Exception ex)
        {

            throw ex;
        }
    }
    #endregion

    #region PASSWORD
    public static string ENCRYPT(this string ClearText)
    {
        byte[] clearData = Encoding.Unicode.GetBytes(ClearText);
        PasswordDeriveBytes bytes = new PasswordDeriveBytes("TRANDUYTHANH_TranPhamManNhi_PHAMTHIXUANDIEU", new byte[] { 0x49, 0x76, 0x61, 110, 0x20, 0x4d, 0x65, 100, 0x76, 0x65, 100, 0x65, 0x76 });
        return Convert.ToBase64String(Encrypt(clearData, bytes.GetBytes(0x20), bytes.GetBytes(0x10)));
    }

    public static byte[] Encrypt(byte[] ClearData, byte[] Key, byte[] IV)
    {
        MemoryStream stream = new MemoryStream();
        Rijndael rijndael = Rijndael.Create();
        rijndael.Key = Key;
        rijndael.IV = IV;
        CryptoStream stream2 = new CryptoStream(stream, rijndael.CreateEncryptor(), CryptoStreamMode.Write);
        stream2.Write(ClearData, 0, ClearData.Length);
        stream2.Close();
        return stream.ToArray();
    }
    #endregion

    public static IPAddress LocalIPAddress()
    {
        if (!System.Net.NetworkInformation.NetworkInterface.GetIsNetworkAvailable())
        {
            return null;
        }

        IPHostEntry host = Dns.GetHostEntry(Dns.GetHostName());

        return host
            .AddressList
            .FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork);
    }
     public static string LocalIPAddressString()
    {
        IPAddress ip = LocalIPAddress();
         if(ip==null)        return "";
         return ip.ToString();
    }
     public static string GetCountryByIP(string ipAddress)
     {
         try
         {
             string strReturnVal;
             string ipResponse = IPRequestHelper("http://ip-api.com/xml/" + ipAddress);

             //return ipResponse;
             XmlDocument ipInfoXML = new XmlDocument();
             ipInfoXML.LoadXml(ipResponse);
             XmlNodeList responseXML = ipInfoXML.GetElementsByTagName("query");

             NameValueCollection dataXML = new NameValueCollection();

             dataXML.Add(responseXML.Item(0).ChildNodes[2].InnerText, responseXML.Item(0).ChildNodes[2].Value);

             strReturnVal = responseXML.Item(0).ChildNodes[1].InnerText.ToString(); // Contry
             strReturnVal += "(" +

            responseXML.Item(0).ChildNodes[2].InnerText.ToString() + ")";  // Contry Code 
             return strReturnVal;
         }
         catch { return "Vietnam(VN)"; }
     }
     public static string IPRequestHelper(string url)
     {

         HttpWebRequest objRequest = (HttpWebRequest)WebRequest.Create(url);
         HttpWebResponse objResponse = (HttpWebResponse)objRequest.GetResponse();

         StreamReader responseStream = new StreamReader(objResponse.GetResponseStream());
         string responseRead = responseStream.ReadToEnd();

         responseStream.Close();
         responseStream.Dispose();

         return responseRead;
     }
     public static string getExternalIp2()
     {
         try
         {
             string externalIP;
             externalIP = (new WebClient()).DownloadString("http://checkip.dyndns.org/");
             externalIP = (new Regex(@"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"))
                          .Matches(externalIP)[0].ToString();
             return externalIP;
         }
         catch { return null; }
     }
     public static string getExternalIp()
     {
         try
         {
             string externalIP;
             externalIP = (new WebClient()).DownloadString("http://myexternalip.com/raw");
             externalIP = (new Regex(@"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"))
                          .Matches(externalIP)[0].ToString();
             return externalIP;
         }
         catch { return null; }
     }
     public static bool IsNetworkAvailable()
     {
         return IsNetworkAvailable(0);
     }
     public static bool IsNetworkAvailable(long minimumSpeed)
     {
         if (!NetworkInterface.GetIsNetworkAvailable())
             return false;

         foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
         {
             // discard because of standard reasons
             if ((ni.OperationalStatus != OperationalStatus.Up) ||
                 (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) ||
                 (ni.NetworkInterfaceType == NetworkInterfaceType.Tunnel))
                 continue;

             // this allow to filter modems, serial, etc.
             // I use 10000000 as a minimum speed for most cases
             if (ni.Speed < minimumSpeed)
                 continue;

             // discard virtual cards (virtual box, virtual pc, etc.)
             if ((ni.Description.IndexOf("virtual", StringComparison.OrdinalIgnoreCase) >= 0) ||
                 (ni.Name.IndexOf("virtual", StringComparison.OrdinalIgnoreCase) >= 0))
                 continue;

             // discard "Microsoft Loopback Adapter", it will not show as NetworkInterfaceType.Loopback but as Ethernet Card.
             if (ni.Description.Equals("Microsoft Loopback Adapter", StringComparison.OrdinalIgnoreCase))
                 continue;

             return true;
         }
         return false;
     }
  }
}
