using System;
using System.Runtime.InteropServices;
using System.ComponentModel;

namespace WnfToWebClient
{
    public class WnfToWebClient
    {
        [DllImport("ntdll.dll")]
        public static extern uint RtlTestAndPublishWnfStateData(
            ref ulong StateName,
            IntPtr TypeId,
            IntPtr Buffer,
            uint Length,
            IntPtr ExplicitScope,
            uint MatchingChangeStamp,
            uint CheckStamp);

        [DllImport("ntdll.dll")]
        public static extern uint NtUpdateWnfStateData(
            ref ulong StateName,
            IntPtr Buffer,
            uint Length,
            IntPtr TypeId,
            IntPtr ExplicitScope,
            uint MatchingChangeStamp,
            uint CheckStamp);

        [DllImport("ntdll.dll")]
        public static extern uint NtQueryWnfStateData(
            ref ulong StateName,
            IntPtr TypeId,
            IntPtr ExplicitScope,
            out uint ChangeStamp,
            IntPtr Buffer,
            ref uint BufferSize);

        [DllImport("ntdll.dll")]
        public static extern uint RtlQueryWnfMetaNotification(
            ref ulong StateName,
            IntPtr Buffer,
            ref uint BufferSize);

        [DllImport("kernel32.dll")]
        public static extern uint GetLastError();

        private const ulong DAB_WNF_STATE = 0x41c64e6da3b6d845; // WebClient State Name (Subject to change across computers and reboots)

        private const uint STATUS_SUCCESS = 0x00000000;
        private const uint STATUS_ACCESS_DENIED = 0xC0000022;
        private const uint STATUS_INVALID_PARAMETER = 0xC000000D;
        private const uint STATUS_BUFFER_TOO_SMALL = 0xC0000023;
        private const uint STATUS_WNF_STATE_NOT_FOUND = 0xC0000720;
        private const uint STATUS_WNF_NO_SUBSCRIBERS = 0xC0000721;

        public static string GetNtStatusDescription(uint status)
        {
            switch (status)
            {
                case STATUS_SUCCESS: return "SUCCESS";
                case STATUS_ACCESS_DENIED: return "ACCESS_DENIED";
                case STATUS_INVALID_PARAMETER: return "INVALID_PARAMETER";
                case STATUS_BUFFER_TOO_SMALL: return "BUFFER_TOO_SMALL";
                case STATUS_WNF_STATE_NOT_FOUND: return "WNF_STATE_NOT_FOUND";
                case STATUS_WNF_NO_SUBSCRIBERS: return "WNF_NO_SUBSCRIBERS";
                case 0xC0000001: return "STATUS_UNSUCCESSFUL";
                case 0xC000000F: return "STATUS_NO_SUCH_FILE";
                default: return $"Unknown (0x{status:X8})";
            }
        }

        public static bool TestWnfState(ulong stateName)
        {
            try
            {
                Console.WriteLine($"Testing WNF state: 0x{stateName:X16}");

                uint bufferSize = 4096;
                byte[] buffer = new byte[bufferSize];
                uint changeStamp = 0;

                GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
                try
                {
                    IntPtr bufferPtr = handle.AddrOfPinnedObject();
                    ulong testState = stateName;

                    uint result = NtQueryWnfStateData(
                        ref testState,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        out changeStamp,
                        bufferPtr,
                        ref bufferSize);

                    Console.WriteLine($"Query result: {GetNtStatusDescription(result)}");
                    Console.WriteLine($"Change stamp: {changeStamp}");
                    Console.WriteLine($"Buffer size: {bufferSize}");

                    return result == STATUS_SUCCESS;
                }
                finally
                {
                    handle.Free();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error testing WNF state: {ex.Message}");
                return false;
            }
        }

        public static bool PublishDabMessage()
        {
            try
            {
                Console.WriteLine("Creating WNF message...");

                byte[] message = new byte[68]; // 0x44 bytes total

                BitConverter.GetBytes((uint)0x000000f3).CopyTo(message, 0);  // Flags
                BitConverter.GetBytes((uint)0xffffffff).CopyTo(message, 4);  // Header marker

                Array.Clear(message, 8, 60);
                BitConverter.GetBytes((uint)245440).CopyTo(message, 56);

                Console.WriteLine("Message created successfully.");
                GCHandle handle = GCHandle.Alloc(message, GCHandleType.Pinned);
                try
                {
                    IntPtr bufferPtr = handle.AddrOfPinnedObject();
                    ulong stateName = DAB_WNF_STATE;
                    Console.WriteLine("Trying NtUpdateWnfStateData...");

                    stateName = DAB_WNF_STATE;
                    uint result = NtUpdateWnfStateData(
                        ref stateName,
                        bufferPtr,
                        68,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        0,
                        0);

                    Console.WriteLine($"NtUpdateWnfStateData result: {GetNtStatusDescription(result)}");

                    if (result == STATUS_SUCCESS)
                    {
                        Console.WriteLine($" Published to state: 0x{stateName:X16}");
                        Console.WriteLine($" Message length: {message.Length} bytes");
                        Console.WriteLine("\nMessage content:");
                        DisplayHexDump(message);

                        return true;
                    }
                    else
                    {
                        Console.WriteLine($" Failed with status: {GetNtStatusDescription(result)}");
                        return false;
                    }
                }
                finally
                {
                    handle.Free();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception publishing WNF message: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
                return false;
            }
        }

        private static void DisplayHexDump(byte[] data)
        {
            for (int i = 0; i < data.Length; i += 16)
            {
                string hex = "";
                string ascii = "";
                for (int j = 0; j < 16 && i + j < data.Length; j++)
                {
                    byte b = data[i + j];
                    hex += $"{b:X2} ";
                    ascii += (b >= 32 && b <= 126) ? (char)b : '.';
                }
                Console.WriteLine($"{i:X4}: {hex.PadRight(48)} {ascii}");
            }
        }

        public static void Main(string[] args)
        {
            Console.WriteLine("WNF to WebClient");
            Console.WriteLine("---");
            Console.WriteLine();

            try
            {
                var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                bool isAdmin = principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
                Console.WriteLine($"Running as Administrator: {isAdmin}");
                Console.WriteLine($"User: {identity.Name}");
                Console.WriteLine();
            }
            catch { }

            if (args.Length > 0 && args[0] == "--test")
            {
                Console.WriteLine("Testing WNF state accessibility...");
                bool canAccess = TestWnfState(DAB_WNF_STATE);
                Console.WriteLine($"Can access WNF state: {canAccess}");
                return;
            }

            if (args.Length > 0 && args[0] == "--force")
            {
                Console.WriteLine("Publishing WNF message...");
                bool success = PublishDabMessage();

                if (!success)
                {
                    Console.WriteLine("Failed: Try with SYSTEM privileges");
                }
            }
            else
            {
                Console.WriteLine("Options:");
                Console.WriteLine("  --test   Test if WNF state is accessible");
                Console.WriteLine("  --force  Publish the WNF message");
                Console.WriteLine();
                Console.WriteLine("Example: WnfPublisher.exe --test");
            }

            Console.WriteLine();
            Console.ReadKey();
        }
    }

    public class WnfStateDecoder
    {
        private const ulong WNF_STATE_KEY = 0x41C64E6DA3BC0074;

        public static void DecodeStateName(ulong encryptedName)
        {
            ulong decrypted = encryptedName ^ WNF_STATE_KEY;

            uint version = (uint)(decrypted & 0xF);
            uint nameLifetime = (uint)((decrypted >> 4) & 0x3);
            uint dataScope = (uint)((decrypted >> 6) & 0xF);
            uint permanentData = (uint)((decrypted >> 10) & 0x1);
            ulong unique = (decrypted >> 11) & 0x1FFFFFFFFFFFFF;

            Console.WriteLine($"WNF State Name Breakdown:");
            Console.WriteLine($"  Raw: 0x{encryptedName:X16}");
            Console.WriteLine($"  Decrypted: 0x{decrypted:X16}");
            Console.WriteLine($"  Version: {version}");
            Console.WriteLine($"  Lifetime: {nameLifetime}");
            Console.WriteLine($"  Scope: {dataScope}");
            Console.WriteLine($"  Permanent: {permanentData}");
            Console.WriteLine($"  Unique: {unique} (0x{unique:X})");
        }
    }
}
