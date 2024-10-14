using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

/*
 * 
 * Credits: Dan Sporici (https://www.codeproject.com/Articles/716227/Csharp-How-to-Scan-a-Process-Memory)
 * I just altered it to work for me.
 * 
 */

namespace memscan
{
    class Program
    {
        public static void Main()
        {
            // these are our settings
            string dump_filename = "dump.bin";
            string string_to_search_for = "Crowbar";
            string process_to_scan = "crowbar";

            // create a dump file (this will be 200+ mb sometimes)
            FileStream fs = new FileStream(dump_filename, FileMode.Create);

            // getting minimum & maximum address
            SYSTEM_INFO sys_info = new SYSTEM_INFO();
            GetSystemInfo(out sys_info);

            Console.WriteLine("Architecture: {0}", sys_info.processorArchitecture.ToString());

            UIntPtr proc_min_address = sys_info.minimumApplicationAddress;
            UIntPtr proc_max_address = sys_info.maximumApplicationAddress;

            // saving the values as long ints so I won't have to do a lot of casts later
            ulong proc_min_address_l = (ulong)proc_min_address;
            ulong proc_max_address_l = (ulong)proc_max_address;

            //Console.WriteLine("Min: {0}, Max: {1}", proc_min_address.ToString("x8"), proc_max_address.ToString("x8"));

            // notepad better be runnin'
            Process process = Process.GetProcessesByName(process_to_scan).FirstOrDefault();
            if (process != null)
            {
                Console.WriteLine("Found process: {0}", process.Id);
            }
            else
            {
                return;
            }

            // opening the process with desired access level
            IntPtr processHandle =
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_WM_READ, false, process.Id);
            Console.WriteLine("Process handle: {0}", processHandle.ToString("x8"));

            // this will store any information we get from VirtualQueryEx()
            MEMORY_BASIC_INFORMATION mem_basic_info = new MEMORY_BASIC_INFORMATION();

            int bytesRead = 0;  // number of bytes read with ReadProcessMemory
            uint bytesReadTotal = 0; // total of bytes read so far

            Console.WriteLine("Proceeding to dump..");

            while (proc_max_address_l>=proc_min_address_l)
            {
                // 28 = sizeof(MEMORY_BASIC_INFORMATION)
                int ret = VirtualQueryEx(processHandle, proc_min_address, out mem_basic_info, 28);
                if (ret == 0) break;

                // if this memory chunk is accessible
                if ((mem_basic_info.Protect != PAGE_GUARD &
                    mem_basic_info.Protect != PAGE_NOACCESS) & mem_basic_info.RegionSize > 0)
                {
                    // Create buffer 
                    byte[] buffer = new byte[mem_basic_info.RegionSize];

                    // read everything in the buffer above
                    ReadProcessMemory((int)processHandle, mem_basic_info.BaseAddress, buffer, mem_basic_info.RegionSize, ref bytesRead);
                    if (bytesRead > 0)
                    {
                        // scan through the memory for your signature 
                        string pattern = string_to_search_for;

                        // convert our string to a byte buffer to be able to compare
                        byte[] pattern_ex = Encoding.UTF8.GetBytes(pattern);

                        // this is our "number of matched character"-counter
                        int j = 0;

                        // traverse memory region
                        for (int i = 0; i < buffer.Length; i++)
                        {
                            // if first character is a match
                            if (buffer[i] == pattern_ex[j])
                            {
                                // get on our own path within the buffer past the recognized character to see if 
                                // more characters match (x is the same as i, but within our traversing context)
                                // a loop within a loop if you will
                                for (int x = i; x < (x + pattern_ex.Length - 1); x++)
                                {
                                    // if our own path matches pattern (from 0-length of pattern)
                                    if (buffer[x] == pattern_ex[j])
                                    {
                                        // number of positive matches increase
                                        j++;
                                    }
                                    else
                                    {
                                        j = 0; break;// mandatory reset of inner counter
                                    }
                                    if (j == pattern_ex.Length - 1)
                                    {
                                        j = 0; // mandatory reset of inner counter
                                        Console.WriteLine("Found it at: {0}", (bytesReadTotal + i));
                                        break;
                                    }
                                }
                            }
                        }

                        // keep track of our distance
                        bytesReadTotal += (uint)buffer.Length;

                        // save to file stream
                        fs.Write(buffer, 0, buffer.Length);
                        fs.Flush();
                    }
                }

                // move to the next memory chunk
                proc_min_address_l += (ulong)mem_basic_info.RegionSize;
                proc_min_address = new UIntPtr(proc_min_address_l);
            }
            Console.WriteLine("Completed");

            CloseHandle(processHandle);
            fs.Close();

            Console.ReadLine();
        }
        #region "Windows stuff"

        // REQUIRED CONSTS

        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int MEM_COMMIT = 0x00001000;
        const int MEM_RESERVE = 0x00002000;
        const int PAGE_GUARD = 0x100;
        const int PAGE_NOACCESS = 0x01;
        const int PAGE_READWRITE = 0x04;
        const int PAGE_EXECUTE_READWRITE = 0x40;
        const int PROCESS_WM_READ = 0x0010;

        // REQUIRED METHODS

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess
             (int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory
        (int hProcess, int lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int VirtualQueryEx(IntPtr hProcess,
        UIntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        static extern int GetLastError();

        // REQUIRED STRUCTS

        public struct MEMORY_BASIC_INFORMATION
        {
            public int BaseAddress;
            public int AllocationBase;
            public int AllocationProtect;
            public int RegionSize;
            public int State;
            public int Protect;
            public int lType;
        }

        public struct SYSTEM_INFO
        {
            public ARCHITECTURE processorArchitecture;
            ushort reserved;
            public uint pageSize;
            public UIntPtr minimumApplicationAddress;
            public UIntPtr maximumApplicationAddress;
            public IntPtr activeProcessorMask;
            public uint numberOfProcessors;
            public uint processorType;
            public uint allocationGranularity;
            public ushort processorLevel;
            public ushort processorRevision;
        }

        public enum ARCHITECTURE : ushort
        {
            PROCESSOR_ARCHITECTURE_AMD64 = 9, // x64 (AMD or Intel)
            PROCESSOR_ARCHITECTURE_ARM = 5,
            PROCESSOR_ARCHITECTURE_ARM64 = 12,
            PROCESSOR_ARCHITECTURE_IA64 = 6,
            PROCESSOR_ARCHITECTURE_INTEL = 0, //x86
            PROCESSOR_ARCHITECTURE_UNKNOWN = 0xffff
        }
        #endregion

    }

}