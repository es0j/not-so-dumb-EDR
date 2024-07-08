using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

using RGiesecke.DllExport;




public static class EdrAgentUtils
{
    [DllExport("MySymbol")]
    public static int MySymbol = 1234;

    [DllExport(CallingConvention.StdCall)]
    public static bool Scan()
    {
        Console.WriteLine("Hello from C#");
        return true;
    }
}

