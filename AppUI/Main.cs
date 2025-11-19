using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using EasyHook;

namespace Pomme
{
    public class IClass
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct PROCESSENTRY32W
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct MODULEENTRY32W
        {
            public uint dwSize;
            public uint th32ModuleID;
            public uint th32ProcessID;
            public uint GlblcntUsage;
            public uint ProccntUsage;
            public IntPtr modBaseAddr;
            public uint modBaseSize;
            public IntPtr hModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string szModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExePath;
        }

        // Windows attend 28 octets et pas 32
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        private struct THREADENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ThreadID;
            public uint th32OwnerProcessID;
            public int tpBasePri;
            public int tpDeltaPri;
            public uint dwFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        private const uint TH32CS_SNAPPROCESS = 0x00000002;
        private const uint TH32CS_SNAPTHREAD = 0x00000004;
        private const uint TH32CS_SNAPMODULE = 0x00000008;
        private const uint TH32CS_SNAPMODULE32 = 0x00000010;

        private const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
        private const uint THREAD_SUSPEND_RESUME = 0x0002;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const uint TOKEN_QUERY = 0x0008;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool Process32FirstW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool Process32NextW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool Module32FirstW(IntPtr hSnapshot, ref MODULEENTRY32W lpme);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool Module32NextW(IntPtr hSnapshot, ref MODULEENTRY32W lpme);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID { public uint LowPart; public int HighPart; }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public PRIVILEGE[] Privileges;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PRIVILEGE { public LUID Luid; public uint Attributes; }
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int LdrLoadDllDelegate(IntPtr PathToFile, uint Flags, ref UNICODE_STRING ModuleFileName, out IntPtr ModuleHandle);
        [ThreadStatic]
        private static bool estDansLeHook;
        private static LocalHook hookChargeurDll;
        private static LdrLoadDllDelegate originalLdrLoadDll;

        public static int IMain(string args = "")
        {
            Console.WriteLine("---  NPGG BYPASS ---");
            Console.WriteLine("Initialisation...");

            bool jaiLesDroits = false;
            jaiLesDroits = ActiverPrivilegesAdmin();

            if (jaiLesDroits == true)
            {
                Console.WriteLine("Admin OK");
            }
            else
            {
                Console.WriteLine("pas de droits admin faut relancer.");
            }

            try
            {
                IntPtr ntdll = LoadLibrary("ntdll.dll");
                IntPtr ldrAddr = GetProcAddress(ntdll, "LdrLoadDll");

                if (ldrAddr != IntPtr.Zero)
                {
                    hookChargeurDll = LocalHook.Create(ldrAddr, new LdrLoadDllDelegate(MonLdrLoadDll), null);
                    hookChargeurDll.ThreadACL.SetInclusiveACL(new int[] { 0 });

                    originalLdrLoadDll = Marshal.GetDelegateForFunctionPointer<LdrLoadDllDelegate>(hookChargeurDll.HookBypassAddress);
                    Console.WriteLine("Hook installé.");
                }
                else
                {
                    Console.WriteLine("Trouve pas LdrLoadDll ");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("erreur dans le hook : " + ex.Message);
                return -1;
            }

            Thread leThread = new Thread(LeThreadPrincipal);
            leThread.IsBackground = true;
            leThread.Start();
            Console.WriteLine("Thread lancé ");

            return 0;
        }

        private static int MonLdrLoadDll(IntPtr PathToFile, uint Flags, ref UNICODE_STRING ModuleFileName, out IntPtr ModuleHandle)
        {
            ModuleHandle = IntPtr.Zero;

            if (estDansLeHook == true)
            {
                return originalLdrLoadDll(PathToFile, Flags, ref ModuleFileName, out ModuleHandle);
            }

            estDansLeHook = true;
            string nomDuFichier = ConvertirNomFichier(ref ModuleFileName);

            bool cEstGameGuard = false;
            if (nomDuFichier.EndsWith("npggNT64.des", StringComparison.OrdinalIgnoreCase))
            {
                cEstGameGuard = true;
            }

            if (cEstGameGuard == true)
            {
                Console.WriteLine("npggNT64.des block");
                estDansLeHook = false;
                return 0; 
            }

            int resultat = originalLdrLoadDll(PathToFile, Flags, ref ModuleFileName, out ModuleHandle);
            estDansLeHook = false;
            return resultat;
        }

        private static string ConvertirNomFichier(ref UNICODE_STRING unicodeString)
        {
            if (unicodeString.Buffer == IntPtr.Zero) return "";
            if (unicodeString.Length == 0) return "";

            return Marshal.PtrToStringUni(unicodeString.Buffer, unicodeString.Length / 2);
        }
        private static void LeThreadPrincipal()
        {
            ActiverPrivilegesAdmin();

            Console.WriteLine("waiting for this mf gameguard, press enter and then launch the game");

            uint lePid = 0;
            lePid = TrouverLePid("GameMon64.des");

            if (lePid != 0)
            {
                Console.WriteLine("PID : " + lePid);

                Thread.Sleep(1000);

                Console.WriteLine("Suspending...");
                bool estSuspendu = EssayerDeSuspendre(lePid);

                if (estSuspendu == true)
                {
                    Console.WriteLine("Success");
                }
                else
                {
                    Console.WriteLine("Fail");
                }

                Console.WriteLine("patch...");
                bool patchReussi = PatcherLeKernel(lePid, "kernel32.dll");

                if (patchReussi == false)
                {
                    Console.WriteLine("Fail");
                    RelancerLeProcess(lePid);
                    return;
                }

                Console.WriteLine("refresh...");
                RelancerLeProcess(lePid);

                Console.WriteLine("Done");
            }
        }

        private static uint TrouverLePid(string nomDuProcessus)
        {
            uint pidTrouve = 0;

            while (true)
            {
                IntPtr hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

                if (hSnapshot.ToInt64() != -1 && hSnapshot != IntPtr.Zero)
                {
                    PROCESSENTRY32W pe = new PROCESSENTRY32W();
                    pe.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32W));

                    if (Process32FirstW(hSnapshot, ref pe))
                    {
                        do
                        {
                            if (pe.szExeFile.Equals(nomDuProcessus, StringComparison.OrdinalIgnoreCase))
                            {
                                pidTrouve = pe.th32ProcessID;
                                break; 
                            }
                        } while (Process32NextW(hSnapshot, ref pe));
                    }
                    CloseHandle(hSnapshot);
                }

                if (pidTrouve != 0)
                {
                    break;
                }

                Thread.Sleep(500);
            }
            return pidTrouve;
        }

        private static bool EssayerDeSuspendre(uint pid)
        {
            int compteur = 0;
            bool resultat = false;

            while (compteur < 20)
            {
                resultat = SuspendreLesThreads(pid);
                if (resultat == true)
                {
                    return true;
                }

                Thread.Sleep(500);
                compteur = compteur + 1;
            }
            return false;
        }

        private static bool SuspendreLesThreads(uint pid)
        {
            IntPtr hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (hSnap.ToInt64() == -1) return false;

            THREADENTRY32 te = new THREADENTRY32();
            //28 sinon ça marche pas
            te.dwSize = 28;

            int nombreDeThreads = 0;

            if (Thread32First(hSnap, ref te))
            {
                do
                {
                    if (te.th32OwnerProcessID == pid)
                    {
                        IntPtr hThread = OpenThread(THREAD_SUSPEND_RESUME, false, te.th32ThreadID);
                        if (hThread != IntPtr.Zero)
                        {
                            SuspendThread(hThread);
                            CloseHandle(hThread);
                            nombreDeThreads++;
                        }
                    }
                } while (Thread32Next(hSnap, ref te));
            }
            CloseHandle(hSnap);

            if (nombreDeThreads > 0)
            {
                Console.WriteLine(nombreDeThreads + " thread a figer");
                return true;
            }
            return false;
        }

        private static bool RelancerLeProcess(uint pid)
        {
            IntPtr hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (hSnap.ToInt64() == -1) return false;

            THREADENTRY32 te = new THREADENTRY32();
            te.dwSize = 28;

            if (Thread32First(hSnap, ref te))
            {
                do
                {
                    if (te.th32OwnerProcessID == pid)
                    {
                        IntPtr hThread = OpenThread(THREAD_SUSPEND_RESUME, false, te.th32ThreadID);
                        if (hThread != IntPtr.Zero)
                        {
                            ResumeThread(hThread);
                            CloseHandle(hThread);
                        }
                    }
                } while (Thread32Next(hSnap, ref te));
            }
            CloseHandle(hSnap);
            return true;
        }

        private static bool PatcherLeKernel(uint pid, string nomModule)
        {
            byte[] codeACopier = { 0xC3 }; 
            uint vieuxDroits;
            IntPtr nbOctetsEcrits;

            //debug ici chelou jrv pas à avoir l'handle     
            IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("Fail handle");
                return false;
            }

            IntPtr adresseDeBase = TrouverAdresseModule(pid, nomModule);
            if (adresseDeBase == IntPtr.Zero)
            {
                CloseHandle(hProcess);
                return false;
            }

            IntPtr localKernel = GetModuleHandle("kernel32.dll");
            IntPtr localOpenProc = GetProcAddress(localKernel, "OpenProcess");

            long decalage = localOpenProc.ToInt64() - localKernel.ToInt64();
            IntPtr adresseFinale = new IntPtr(adresseDeBase.ToInt64() + decalage);

            // chagner les droits des pages
            bool resultProtect = VirtualProtectEx(hProcess, adresseFinale, 1, PAGE_EXECUTE_READWRITE, out vieuxDroits);
            if (resultProtect == false)
            {
                Console.WriteLine("VirtualProtectEx fail.");
                CloseHandle(hProcess);
                return false;
            }

            bool resultWrite = WriteProcessMemory(hProcess, adresseFinale, codeACopier, 1, out nbOctetsEcrits);
            if (resultWrite == false)
            {
                Console.WriteLine("wpm fail.");
                CloseHandle(hProcess);
                return false;
            }

            // Et normalement la on est good 
            VirtualProtectEx(hProcess, adresseFinale, 1, vieuxDroits, out vieuxDroits);
            CloseHandle(hProcess);

            return true;
        }

        private static IntPtr TrouverAdresseModule(uint pid, string nomModule)
        {
            IntPtr hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
            if (hSnap.ToInt64() == -1) return IntPtr.Zero;

            MODULEENTRY32W me = new MODULEENTRY32W();
            me.dwSize = (uint)Marshal.SizeOf(typeof(MODULEENTRY32W));
            IntPtr adresseTrouvee = IntPtr.Zero;

            if (Module32FirstW(hSnap, ref me))
            {
                do
                {
                    if (me.szModule.Equals(nomModule, StringComparison.OrdinalIgnoreCase))
                    {
                        adresseTrouvee = me.modBaseAddr;
                        break;
                    }
                } while (Module32NextW(hSnap, ref me));
            }
            CloseHandle(hSnap);
            return adresseTrouvee;
        }

        private static bool ActiverPrivilegesAdmin()
        {
            IntPtr hToken;
            bool resToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken);

            if (resToken == false)
            {
                return false;
            }

            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.PrivilegeCount = 1;
            tp.Privileges = new PRIVILEGE[1];
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            bool resLookup = LookupPrivilegeValue(null, "SeDebugPrivilege", out tp.Privileges[0].Luid);
            if (resLookup == true)
            {
                AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            }

            CloseHandle(hToken);
            return true;
        }
    }
}
