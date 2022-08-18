using System.Net;
using System.Net.Sockets;

namespace Identity
{
    public class Utils
    {
        public static string GetLocalIPAddress()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            var ipAddress = host.AddressList.FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork);
            return ipAddress?.ToString() ?? string.Empty;
        }
    }
}
