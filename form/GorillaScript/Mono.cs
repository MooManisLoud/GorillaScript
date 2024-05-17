using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace GorillaScript
{
    class MonoInjection
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessRights dwDesiredAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);

        [DllImport("psapi.dll", SetLastError = true)]
        public static extern bool EnumProcessModulesEx(IntPtr hProcess, [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)][In][Out] IntPtr[] lphModule, int cb, [MarshalAs(UnmanagedType.U4)] out int lpcbNeeded, ModuleFilter dwFilterFlag);

        [DllImport("psapi.dll")]
        public static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, [In][MarshalAs(UnmanagedType.U4)] uint nSize);

        [DllImport("psapi.dll", SetLastError = true)]
        public static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out MODULEINFO lpmodinfo, uint cb);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, int lpNumberOfBytesWritten = 0);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, int lpNumberOfBytesRead = 0);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, MemoryFreeType dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, int dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, ThreadCreationFlags dwCreationFlags, out int lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern WaitResult WaitForSingleObject(IntPtr hHandle, int dwMilliseconds);
        [StructLayout(LayoutKind.Sequential)]
        public struct MODULEINFO
        {
            public IntPtr lpBaseOfDll;

            public int SizeOfImage;

            public IntPtr EntryPoint;
        }

        public enum ModuleFilter : uint
        {
            LIST_MODULES_DEFAULT = 0x0,
            LIST_MODULES_32BIT = 0x01,
            LIST_MODULES_64BIT = 0x02,
            LIST_MODULES_ALL = 0x03
        }
        public enum MonoImageOpenStatus
        {
            MONO_IMAGE_OK,
            MONO_IMAGE_ERROR_ERRNO,
            MONO_IMAGE_MISSING_ASSEMBLYREF,
            MONO_IMAGE_IMAGE_INVALID
        }

        [Flags]
        public enum AllocationType
        {
            MEM_COMMIT = 0x00001000,
            MEM_RESERVE = 0x00002000,
            MEM_RESET = 0x00080000,
            MEM_RESET_UNDO = 0x1000000,
            MEM_LARGE_PAGES = 0x20000000,
            MEM_PHYSICAL = 0x00400000,
            MEM_TOP_DOWN = 0x00100000
        }

        [Flags]
        public enum MemoryProtection
        {
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x4,
            PAGE_WRITECOPY = 0x8,
            PAGE_TARGETS_INVALID = 0x40000000,
            PAGE_TARGETS_NO_UPDATE = 0x40000000,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400
        }

        [Flags]
        public enum MemoryFreeType
        {
            MEM_DECOMMIT = 0x4000,
            MEM_RELEASE = 0x8000
        }

        [Flags]
        public enum ThreadCreationFlags
        {
            None = 0,
            CREATE_SUSPENDED = 0x00000004,
            STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000
        }

        public enum WaitResult : uint
        {
            WAIT_ABANDONED = 0x00000080,
            WAIT_OBJECT_0 = 0x00000000,
            WAIT_TIMEOUT = 0x00000102,
            WAIT_FAILED = 0xFFFFFFFF
        }

        [Flags]
        public enum ProcessAccessRights : uint
        {
            PROCESS_ALL_ACCESS = 0x1FFFFF,
            PROCESS_CREATE_PROCESS = 0x0080,
            PROCESS_CREATE_THREAD = 0x0002,
            PROCESS_DUP_HANDLE = 0x0040,
            PROCESS_QUERY_INFORMATION = 0x0400,
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
            PROCESS_SET_INFORMATION = 0x0200,
            PROCESS_SET_QUOTA = 0x0100,
            PROCESS_SUSPEND_RESUME = 0x0800,
            PROCESS_TERMINATE = 0x0001,
            PROCESS_VM_OPERATION = 0x0008,
            PROCESS_VM_READ = 0x0010,
            PROCESS_VM_WRITE = 0x0020,
            SYNCHRONIZE = 0x00100000
        }
        public static IEnumerable<ExportedFunction> GetExportedFunctions(IntPtr handle, IntPtr mod)
        {
            using (Memory memory = new Memory(handle))
            {
                int e_lfanew = memory.ReadInt(mod + 0x3C);
                IntPtr ntHeaders = mod + e_lfanew;
                IntPtr optionalHeader = ntHeaders + 0x18;
                IntPtr dataDirectory = optionalHeader + (Is64BitProcess(handle) ? 0x70 : 0x60);
                IntPtr exportDirectory = mod + memory.ReadInt(dataDirectory);
                IntPtr names = mod + memory.ReadInt(exportDirectory + 0x20);
                IntPtr ordinals = mod + memory.ReadInt(exportDirectory + 0x24);
                IntPtr functions = mod + memory.ReadInt(exportDirectory + 0x1C);
                int count = memory.ReadInt(exportDirectory + 0x18);

                for (int i = 0; i < count; i++)
                {
                    int offset = memory.ReadInt(names + i * 4);
                    string name = memory.ReadString(mod + offset, 32, Encoding.ASCII);
                    short ordinal = memory.ReadShort(ordinals + i * 2);
                    IntPtr address = mod + memory.ReadInt(functions + ordinal * 4);

                    if (address != IntPtr.Zero)
                        yield return new ExportedFunction(name, address);
                }
            }
        }

        public static bool GetMonoModule(IntPtr handle, out IntPtr monoModule)
        {
            int size = Is64BitProcess(handle) ? 8 : 4;

            IntPtr[] ptrs = new IntPtr[0];

            if (!EnumProcessModulesEx(
                handle, ptrs, 0, out int bytesNeeded, ModuleFilter.LIST_MODULES_ALL))
            {
                throw new InjectorException("Failed to enumerate process modules", new Win32Exception(Marshal.GetLastWin32Error()));
            }

            int count = bytesNeeded / size;
            ptrs = new IntPtr[count];

            if (!EnumProcessModulesEx(
                handle, ptrs, bytesNeeded, out bytesNeeded, ModuleFilter.LIST_MODULES_ALL))
            {
                throw new InjectorException("Failed to enumerate process modules", new Win32Exception(Marshal.GetLastWin32Error()));
            }

            for (int i = 0; i < count; i++)
            {
                StringBuilder path = new StringBuilder(260);
                GetModuleFileNameEx(handle, ptrs[i], path, 260);

                if (path.ToString().IndexOf("mono", StringComparison.OrdinalIgnoreCase) > -1)
                {
                    if (!GetModuleInformation(handle, ptrs[i], out MODULEINFO info, (uint)(size * ptrs.Length)))
                        throw new InjectorException("Failed to get module information", new Win32Exception(Marshal.GetLastWin32Error()));

                    var funcs = GetExportedFunctions(handle, info.lpBaseOfDll);

                    if (funcs.Any(f => f.Name == "mono_get_root_domain"))
                    {
                        monoModule = info.lpBaseOfDll;
                        return true;
                    }
                }
            }

            monoModule = IntPtr.Zero;
            return false;
        }

        public static bool Is64BitProcess(IntPtr handle)
        {
            if (!Environment.Is64BitOperatingSystem)
                return false;

            if (!IsWow64Process(handle, out bool isWow64))
                return IntPtr.Size == 8; // assume it's the same as the current process

            return !isWow64;
        }
        public class Injector : IDisposable
        {
            private const string mono_get_root_domain = "mono_get_root_domain";

            private const string mono_thread_attach = "mono_thread_attach";

            private const string mono_image_open_from_data = "mono_image_open_from_data";

            private const string mono_assembly_load_from_full = "mono_assembly_load_from_full";

            private const string mono_assembly_get_image = "mono_assembly_get_image";

            private const string mono_class_from_name = "mono_class_from_name";

            private const string mono_class_get_method_from_name = "mono_class_get_method_from_name";

            private const string mono_runtime_invoke = "mono_runtime_invoke";

            private const string mono_assembly_close = "mono_assembly_close";

            private const string mono_image_strerror = "mono_image_strerror";

            private const string mono_object_get_class = "mono_object_get_class";

            private const string mono_class_get_name = "mono_class_get_name";

            private readonly Dictionary<string, IntPtr> Exports = new Dictionary<string, IntPtr>
        {
            { mono_get_root_domain, IntPtr.Zero },
            { mono_thread_attach, IntPtr.Zero },
            { mono_image_open_from_data, IntPtr.Zero },
            { mono_assembly_load_from_full, IntPtr.Zero },
            { mono_assembly_get_image, IntPtr.Zero },
            { mono_class_from_name, IntPtr.Zero },
            { mono_class_get_method_from_name, IntPtr.Zero },
            { mono_runtime_invoke, IntPtr.Zero },
            { mono_assembly_close, IntPtr.Zero },
            { mono_image_strerror, IntPtr.Zero },
            { mono_object_get_class, IntPtr.Zero },
            { mono_class_get_name, IntPtr.Zero }
        };

            private Memory _memory;

            private IntPtr _rootDomain;

            private bool _attach;

            private readonly IntPtr _handle;

            private IntPtr _mono;

            public bool Is64Bit { get; private set; }

            public Injector(string processName)
            {
                Process process = Process.GetProcesses()
                    .FirstOrDefault(p => p.ProcessName
                    .Equals(processName, StringComparison.OrdinalIgnoreCase));

                if (process == null)
                    throw new InjectorException($"Could not find a process with the name {processName}");

                if ((_handle = OpenProcess(ProcessAccessRights.PROCESS_ALL_ACCESS, false, process.Id)) == IntPtr.Zero)
                    throw new InjectorException("Failed to open process", new Win32Exception(Marshal.GetLastWin32Error()));

                Is64Bit = Is64BitProcess(_handle);

                if (!GetMonoModule(_handle, out _mono))
                    throw new InjectorException("Failed to find mono.dll in the target process");

                _memory = new Memory(_handle);
            }

            public Injector(int processId)
            {
                Process process = Process.GetProcesses()
                    .FirstOrDefault(p => p.Id == processId);

                if (process == null)
                    throw new InjectorException($"Could not find a process with the id {processId}");

                if ((_handle = OpenProcess(ProcessAccessRights.PROCESS_ALL_ACCESS, false, process.Id)) == IntPtr.Zero)
                    throw new InjectorException("Failed to open process", new Win32Exception(Marshal.GetLastWin32Error()));

                Is64Bit = Is64BitProcess(_handle);

                if (!GetMonoModule(_handle, out _mono))
                    throw new InjectorException("Failed to find mono.dll in the target process");

                _memory = new Memory(_handle);
            }

            public Injector(IntPtr processHandle, IntPtr monoModule)
            {
                if ((_handle = processHandle) == IntPtr.Zero)
                    throw new ArgumentException("Argument cannot be zero", nameof(processHandle));

                if ((_mono = monoModule) == IntPtr.Zero)
                    throw new ArgumentException("Argument cannot be zero", nameof(monoModule));

                Is64Bit = Is64BitProcess(_handle);
                _memory = new Memory(_handle);
            }

            public void Dispose()
            {
                _memory.Dispose();
                CloseHandle(_handle);
            }

            private void ObtainMonoExports()
            {
                foreach (ExportedFunction ef in GetExportedFunctions(_handle, _mono))
                    if (Exports.ContainsKey(ef.Name))
                        Exports[ef.Name] = ef.Address;

                foreach (var kvp in Exports)
                    if (kvp.Value == IntPtr.Zero)
                        throw new InjectorException($"Failed to obtain the address of {kvp.Key}()");
            }

            public IntPtr Inject(byte[] rawAssembly, string @namespace, string className, string methodName)
            {
                if (rawAssembly == null)
                    throw new ArgumentNullException(nameof(rawAssembly));

                if (rawAssembly.Length == 0)
                    throw new ArgumentException($"{nameof(rawAssembly)} cannot be empty", nameof(rawAssembly));

                if (className == null)
                    throw new ArgumentNullException(nameof(className));

                if (methodName == null)
                    throw new ArgumentNullException(nameof(methodName));

                IntPtr rawImage, assembly, image, @class, method;

                ObtainMonoExports();
                _rootDomain = GetRootDomain();
                rawImage = OpenImageFromData(rawAssembly);
                _attach = true;
                assembly = OpenAssemblyFromImage(rawImage);
                image = GetImageFromAssembly(assembly);
                @class = GetClassFromName(image, @namespace, className);
                method = GetMethodFromName(@class, methodName);
                RuntimeInvoke(method);
                return assembly;
            }

            public void Eject(IntPtr assembly, string @namespace, string className, string methodName)
            {
                if (assembly == IntPtr.Zero)
                    throw new ArgumentException($"{nameof(assembly)} cannot be zero", nameof(assembly));

                if (className == null)
                    throw new ArgumentNullException(nameof(className));

                if (methodName == null)
                    throw new ArgumentNullException(nameof(methodName));

                IntPtr image, @class, method;

                ObtainMonoExports();
                _rootDomain = GetRootDomain();
                _attach = true;
                image = GetImageFromAssembly(assembly);
                @class = GetClassFromName(image, @namespace, className);
                method = GetMethodFromName(@class, methodName);
                RuntimeInvoke(method);
                CloseAssembly(assembly);
            }

            private static void ThrowIfNull(IntPtr ptr, string methodName)
            {
                if (ptr == IntPtr.Zero)
                    throw new InjectorException($"{methodName}() returned NULL");
            }

            private IntPtr GetRootDomain()
            {
                IntPtr rootDomain = Execute(Exports[mono_get_root_domain]);
                ThrowIfNull(rootDomain, mono_get_root_domain);
                return rootDomain;
            }

            private IntPtr OpenImageFromData(byte[] assembly)
            {
                IntPtr statusPtr = _memory.Allocate(4);
                IntPtr rawImage = Execute(Exports[mono_image_open_from_data],
                    _memory.AllocateAndWrite(assembly), (IntPtr)assembly.Length, (IntPtr)1, statusPtr);

                MonoImageOpenStatus status = (MonoImageOpenStatus)_memory.ReadInt(statusPtr);

                if (status != MonoImageOpenStatus.MONO_IMAGE_OK)
                {
                    IntPtr messagePtr = Execute(Exports[mono_image_strerror], (IntPtr)status);
                    string message = _memory.ReadString(messagePtr, 256, Encoding.UTF8);
                    throw new InjectorException($"{mono_image_open_from_data}() failed: {message}");
                }

                return rawImage;
            }

            private IntPtr OpenAssemblyFromImage(IntPtr image)
            {
                IntPtr statusPtr = _memory.Allocate(4);
                IntPtr assembly = Execute(Exports[mono_assembly_load_from_full],
                    image, _memory.AllocateAndWrite(new byte[1]), statusPtr, IntPtr.Zero);

                MonoImageOpenStatus status = (MonoImageOpenStatus)_memory.ReadInt(statusPtr);

                if (status != MonoImageOpenStatus.MONO_IMAGE_OK)
                {
                    IntPtr messagePtr = Execute(Exports[mono_image_strerror], (IntPtr)status);
                    string message = _memory.ReadString(messagePtr, 256, Encoding.UTF8);
                    throw new InjectorException($"{mono_assembly_load_from_full}() failed: {message}");
                }

                return assembly;
            }

            private IntPtr GetImageFromAssembly(IntPtr assembly)
            {
                IntPtr image = Execute(Exports[mono_assembly_get_image], assembly);
                ThrowIfNull(image, mono_assembly_get_image);
                return image;
            }

            private IntPtr GetClassFromName(IntPtr image, string @namespace, string className)
            {
                IntPtr @class = Execute(Exports[mono_class_from_name],
                    image, _memory.AllocateAndWrite(@namespace), _memory.AllocateAndWrite(className));
                ThrowIfNull(@class, mono_class_from_name);
                return @class;
            }

            private IntPtr GetMethodFromName(IntPtr @class, string methodName)
            {
                IntPtr method = Execute(Exports[mono_class_get_method_from_name],
                    @class, _memory.AllocateAndWrite(methodName), IntPtr.Zero);
                ThrowIfNull(method, mono_class_get_method_from_name);
                return method;
            }

            private string GetClassName(IntPtr monoObject)
            {
                IntPtr @class = Execute(Exports[mono_object_get_class], monoObject);
                ThrowIfNull(@class, mono_object_get_class);
                IntPtr className = Execute(Exports[mono_class_get_name], @class);
                ThrowIfNull(className, mono_class_get_name);
                return _memory.ReadString(className, 256, Encoding.UTF8);
            }

            private string ReadMonoString(IntPtr monoString)
            {
                int len = _memory.ReadInt(monoString + (Is64Bit ? 0x10 : 0x8));
                return _memory.ReadUnicodeString(monoString + (Is64Bit ? 0x14 : 0xC), len * 2);
            }

            private void RuntimeInvoke(IntPtr method)
            {
                IntPtr excPtr = Is64Bit ? _memory.AllocateAndWrite((long)0) : _memory.AllocateAndWrite(0);

                IntPtr result = Execute(Exports[mono_runtime_invoke],
                    method, IntPtr.Zero, IntPtr.Zero, excPtr);

                IntPtr exc = (IntPtr)_memory.ReadInt(excPtr);

                if (exc != IntPtr.Zero)
                {
                    string className = GetClassName(exc);
                    string message = ReadMonoString((IntPtr)_memory.ReadInt(exc + (Is64Bit ? 0x20 : 0x10)));
                    throw new InjectorException($"The managed method threw an exception: ({className}) {message}");
                }
            }

            private void CloseAssembly(IntPtr assembly)
            {
                IntPtr result = Execute(Exports[mono_assembly_close], assembly);
                ThrowIfNull(result, mono_assembly_close);
            }

            private IntPtr Execute(IntPtr address, params IntPtr[] args)
            {
                IntPtr retValPtr = Is64Bit
                    ? _memory.AllocateAndWrite((long)0)
                    : _memory.AllocateAndWrite(0);

                byte[] code = Assemble(address, retValPtr, args);
                IntPtr alloc = _memory.AllocateAndWrite(code);

                IntPtr thread = CreateRemoteThread(
                    _handle, IntPtr.Zero, 0, alloc, IntPtr.Zero, 0, out _);

                if (thread == IntPtr.Zero)
                    throw new InjectorException("Failed to create a remote thread", new Win32Exception(Marshal.GetLastWin32Error()));

                WaitResult result = WaitForSingleObject(thread, -1);

                if (result == WaitResult.WAIT_FAILED)
                    throw new InjectorException("Failed to wait for a remote thread", new Win32Exception(Marshal.GetLastWin32Error()));

                IntPtr ret = Is64Bit
                    ? (IntPtr)_memory.ReadLong(retValPtr)
                    : (IntPtr)_memory.ReadInt(retValPtr);

                if ((long)ret == 0x00000000C0000005)
                    throw new InjectorException($"An access violation occurred while executing {Exports.First(e => e.Value == address).Key}()");

                return ret;
            }

            private byte[] Assemble(IntPtr functionPtr, IntPtr retValPtr, IntPtr[] args)
            {
                return Is64Bit
                    ? Assemble64(functionPtr, retValPtr, args)
                    : Assemble86(functionPtr, retValPtr, args);
            }

            private byte[] Assemble86(IntPtr functionPtr, IntPtr retValPtr, IntPtr[] args)
            {
                Assembler asm = new Assembler();

                if (_attach)
                {
                    asm.Push(_rootDomain);
                    asm.MovEax(Exports[mono_thread_attach]);
                    asm.CallEax();
                    asm.AddEsp(4);
                }

                for (int i = args.Length - 1; i >= 0; i--)
                    asm.Push(args[i]);

                asm.MovEax(functionPtr);
                asm.CallEax();
                asm.AddEsp((byte)(args.Length * 4));
                asm.MovEaxTo(retValPtr);
                asm.Return();

                return asm.ToByteArray();
            }

            private byte[] Assemble64(IntPtr functionPtr, IntPtr retValPtr, IntPtr[] args)
            {
                Assembler asm = new Assembler();

                asm.SubRsp(40);

                if (_attach)
                {
                    asm.MovRax(Exports[mono_thread_attach]);
                    asm.MovRcx(_rootDomain);
                    asm.CallRax();
                }

                asm.MovRax(functionPtr);

                for (int i = 0; i < args.Length; i++)
                {
                    switch (i)
                    {
                        case 0:
                            asm.MovRcx(args[i]);
                            break;
                        case 1:
                            asm.MovRdx(args[i]);
                            break;
                        case 2:
                            asm.MovR8(args[i]);
                            break;
                        case 3:
                            asm.MovR9(args[i]);
                            break;
                    }
                }

                asm.CallRax();
                asm.AddRsp(40);
                asm.MovRaxTo(retValPtr);
                asm.Return();

                return asm.ToByteArray();
            }
        }
        public class Memory : IDisposable
        {
            private readonly IntPtr _handle;

            private readonly Dictionary<IntPtr, int> _allocations = new Dictionary<IntPtr, int>();

            public Memory(IntPtr processHandle)
            {
                _handle = processHandle;
            }

            public string ReadString(IntPtr address, int length, Encoding encoding)
            {
                List<byte> bytes = new List<byte>();

                for (int i = 0; i < length; i++)
                {
                    byte read = ReadBytes(address + bytes.Count, 1)[0];

                    if (read == 0x00)
                        break;

                    bytes.Add(read);
                }

                return encoding.GetString(bytes.ToArray());
            }

            public string ReadUnicodeString(IntPtr address, int length)
            {
                return Encoding.Unicode.GetString(ReadBytes(address, length));
            }

            public short ReadShort(IntPtr address)
            {
                return BitConverter.ToInt16(ReadBytes(address, 2), 0);
            }

            public int ReadInt(IntPtr address)
            {
                return BitConverter.ToInt32(ReadBytes(address, 4), 0);
            }

            public long ReadLong(IntPtr address)
            {
                return BitConverter.ToInt64(ReadBytes(address, 8), 0);
            }

            public byte[] ReadBytes(IntPtr address, int size)
            {
                byte[] bytes = new byte[size];

                if (!ReadProcessMemory(_handle, address, bytes, size))
                    throw new InjectorException("Failed to read process memory", new Win32Exception(Marshal.GetLastWin32Error()));

                return bytes;
            }

            public IntPtr AllocateAndWrite(byte[] data)
            {
                IntPtr addr = Allocate(data.Length);
                Write(addr, data);
                return addr;
            }

            public IntPtr AllocateAndWrite(string data) => AllocateAndWrite(Encoding.UTF8.GetBytes(data));

            public IntPtr AllocateAndWrite(int data) => AllocateAndWrite(BitConverter.GetBytes(data));

            public IntPtr AllocateAndWrite(long data) => AllocateAndWrite(BitConverter.GetBytes(data));

            public IntPtr Allocate(int size)
            {
                IntPtr addr =
                    VirtualAllocEx(_handle, IntPtr.Zero, size,
                        AllocationType.MEM_COMMIT, MemoryProtection.PAGE_EXECUTE_READWRITE);

                if (addr == IntPtr.Zero)
                    throw new InjectorException("Failed to allocate process memory", new Win32Exception(Marshal.GetLastWin32Error()));

                _allocations.Add(addr, size);
                return addr;
            }

            public void Write(IntPtr addr, byte[] data)
            {
                if (!WriteProcessMemory(_handle, addr, data, data.Length))
                    throw new InjectorException("Failed to write process memory", new Win32Exception(Marshal.GetLastWin32Error()));
            }

            public void Dispose()
            {
                foreach (var kvp in _allocations)
                    VirtualFreeEx(_handle, kvp.Key, kvp.Value, MemoryFreeType.MEM_DECOMMIT);
            }
        }
        public class Assembler
        {
            private readonly List<byte> _asm = new List<byte>();

            public void MovRax(IntPtr arg)
            {
                _asm.AddRange(new byte[] { 0x48, 0xB8 });
                _asm.AddRange(BitConverter.GetBytes((long)arg));
            }

            public void MovRcx(IntPtr arg)
            {
                _asm.AddRange(new byte[] { 0x48, 0xB9 });
                _asm.AddRange(BitConverter.GetBytes((long)arg));
            }

            public void MovRdx(IntPtr arg)
            {
                _asm.AddRange(new byte[] { 0x48, 0xBA });
                _asm.AddRange(BitConverter.GetBytes((long)arg));
            }

            public void MovR8(IntPtr arg)
            {
                _asm.AddRange(new byte[] { 0x49, 0xB8 });
                _asm.AddRange(BitConverter.GetBytes((long)arg));
            }

            public void MovR9(IntPtr arg)
            {
                _asm.AddRange(new byte[] { 0x49, 0xB9 });
                _asm.AddRange(BitConverter.GetBytes((long)arg));
            }

            public void SubRsp(byte arg)
            {
                _asm.AddRange(new byte[] { 0x48, 0x83, 0xEC });
                _asm.Add(arg);
            }

            public void CallRax()
            {
                _asm.AddRange(new byte[] { 0xFF, 0xD0 });
            }

            public void AddRsp(byte arg)
            {
                _asm.AddRange(new byte[] { 0x48, 0x83, 0xC4 });
                _asm.Add(arg);
            }

            public void MovRaxTo(IntPtr dest)
            {
                _asm.AddRange(new byte[] { 0x48, 0xA3 });
                _asm.AddRange(BitConverter.GetBytes((long)dest));
            }

            public void Push(IntPtr arg)
            {
                _asm.Add((int)arg < 128 ? (byte)0x6A : (byte)0x68);
                _asm.AddRange((int)arg <= 255 ? new[] { (byte)arg } : BitConverter.GetBytes((int)arg));
            }

            public void MovEax(IntPtr arg)
            {
                _asm.Add(0xB8);
                _asm.AddRange(BitConverter.GetBytes((int)arg));
            }

            public void CallEax()
            {
                _asm.AddRange(new byte[] { 0xFF, 0xD0 });
            }

            public void AddEsp(byte arg)
            {
                _asm.AddRange(new byte[] { 0x83, 0xC4 });
                _asm.Add(arg);
            }

            public void MovEaxTo(IntPtr dest)
            {
                _asm.Add(0xA3);
                _asm.AddRange(BitConverter.GetBytes((int)dest));
            }

            public void Return()
            {
                _asm.Add(0xC3);
            }

            public byte[] ToByteArray() => _asm.ToArray();
        }
        public class InjectorException : Exception
        {
            public InjectorException(string message) : base(message)
            {
            }

            public InjectorException(string message, Exception innerException) : base(message, innerException)
            {
            }
        }

        public struct ExportedFunction
        {
            public string Name;

            public IntPtr Address;

            public ExportedFunction(string name, IntPtr address)
            {
                Name = name;
                Address = address;
            }
        }
    }
}
