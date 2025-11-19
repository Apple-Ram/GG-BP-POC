using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace Injector
{
    class Program
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        const int PROCESS_CREATE_THREAD = 0x0002;
        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int PROCESS_VM_OPERATION = 0x0008;
        const int PROCESS_VM_WRITE = 0x0020;
        const int PROCESS_VM_READ = 0x0010;
        const int MEM_COMMIT = 0x1000;
        const int MEM_RESERVE = 0x2000;
        const int PAGE_READWRITE = 0x04;

        static void Main(string[] args)
        {
            // Récupération du chemin de la DLL
            string cheminDll = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "LoaderApp.dll");

            // Vérification de la présence du fichier
            if (!File.Exists(cheminDll))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"please put both dll in same path as this .exe");
                Console.ResetColor();
                Console.ReadLine();
                return;
            }

            Console.WriteLine("waiting for cheat engine...");

            int pidCible = 0;

            while (true)
            {
                pidCible = TrouverCheatEngineAuto();

                if (pidCible != 0)
                {
                    Console.WriteLine($"\nFound cheat engine ");

                    bool resultat = InjecterDll(pidCible, cheminDll);

                    if (resultat)
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("SUCCESS.");
                        Console.ResetColor();
                        break; 
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("FAIL");
                        Console.ResetColor();
                        Thread.Sleep(2000);
                    }
                }
                else
                {
                    Thread.Sleep(1000);
                }
            }
        }


        static int TrouverCheatEngineAuto()
        {
            Process[] listeProcess = Process.GetProcesses();
            foreach (Process p in listeProcess)
            {
                string nom = p.ProcessName.ToLower();

                if (nom.Contains("cheatengine"))
                {
                    Console.WriteLine($"found {p.ProcessName}");
                    return p.Id;
                }
            }

            return 0;
        }

        static bool InjecterDll(int pid, string cheminDll)
        {
            try
            {
                IntPtr hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, pid);
                if (hProcess == IntPtr.Zero)
                {
                    Console.WriteLine("fail 2.");
                    return false;
                }
                IntPtr allocMemAddress = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)((cheminDll.Length + 1) * Marshal.SizeOf(typeof(char))), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

                if (allocMemAddress == IntPtr.Zero)
                {
                    Console.WriteLine("virtualalloc fail");
                    return false;
                }

                UIntPtr bytesWritten;
                byte[] buffer = Encoding.Default.GetBytes(cheminDll); 
                WriteProcessMemory(hProcess, allocMemAddress, buffer, (uint)buffer.Length, out bytesWritten);

                IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

                if (loadLibraryAddr == IntPtr.Zero)
                {
                    Console.WriteLine("fail 3.");
                    return false;
                }                IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLibraryAddr, allocMemAddress, 0, IntPtr.Zero);

                if (hThread == IntPtr.Zero)
                {
                    Console.WriteLine("fail 4");
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("exception : " + ex.Message);
                return false;
            }
        }
    }
}
