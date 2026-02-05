using System.Runtime.InteropServices;

namespace dotNetPELoader
{
    internal class Program
    {
        /* Name: dotNetPELoader
         * Author: ISSAC
         * Github: https://github.com/iss4cf0ng/dotNetPELoader
         * Version: 1.0.0
         */

        static string szBanner = "      $$\\            $$\\     $$\\   $$\\            $$\\                          \r\n      $$ |           $$ |    $$$\\  $$ |           $$ |                         \r\n $$$$$$$ | $$$$$$\\ $$$$$$\\   $$$$\\ $$ | $$$$$$\\ $$$$$$\\                        \r\n$$  __$$ |$$  __$$\\\\_$$  _|  $$ $$\\$$ |$$  __$$\\\\_$$  _|                       \r\n$$ /  $$ |$$ /  $$ | $$ |    $$ \\$$$$ |$$$$$$$$ | $$ |                         \r\n$$ |  $$ |$$ |  $$ | $$ |$$\\ $$ |\\$$$ |$$   ____| $$ |$$\\                      \r\n\\$$$$$$$ |\\$$$$$$  | \\$$$$  |$$ | \\$$ |\\$$$$$$$\\  \\$$$$  |                     \r\n \\_______| \\______/   \\____/ \\__|  \\__| \\_______|  \\____/                      \r\n                                                                               \r\n                                                                               \r\n                                                                               \r\n$$$$$$$\\  $$$$$$$$\\ $$\\                                $$\\                     \r\n$$  __$$\\ $$  _____|$$ |                               $$ |                    \r\n$$ |  $$ |$$ |      $$ |      $$$$$$\\   $$$$$$\\   $$$$$$$ | $$$$$$\\   $$$$$$\\  \r\n$$$$$$$  |$$$$$\\    $$ |     $$  __$$\\  \\____$$\\ $$  __$$ |$$  __$$\\ $$  __$$\\ \r\n$$  ____/ $$  __|   $$ |     $$ /  $$ | $$$$$$$ |$$ /  $$ |$$$$$$$$ |$$ |  \\__|\r\n$$ |      $$ |      $$ |     $$ |  $$ |$$  __$$ |$$ |  $$ |$$   ____|$$ |      \r\n$$ |      $$$$$$$$\\ $$$$$$$$\\\\$$$$$$  |\\$$$$$$$ |\\$$$$$$$ |\\$$$$$$$\\ $$ |      \r\n\\__|      \\________|\\________|\\______/  \\_______| \\_______| \\_______|\\__|      \r\n                                                                               \r\n                                                                               \r\n                                                                               ";
        static string szDescription = "" +
            "Author: ISSAC\n" +
            "Github: https://github.com/iss4cf0ng/dotNetPELoader";
        static string szUsage = "" +
            "Example:\n" +
            "\tdotNetPELoader.exe --x86 FilePath\n" +
            "\tdotNetPELoader.exe --x64 FilePath\n" +
            "\tdotNetPELoader.exe --coffee";
        static string szCoffee = "    (  )   (   )  )\r\n     ) (   )  (  (\r\n     ( )  (    ) )\r\n     _____________\r\n    <_____________> ___\r\n    |             |/ _ \\\r\n    |               | | |\r\n    |               |_| |\r\n ___|             |\\___/\r\n/    \\___________/    \\\r\n\\_____________________/\r\n";

        static void Main(string[] args)
        {
            Console.WriteLine(szBanner);
            Console.WriteLine(szDescription);

            fnLogInfo($"The current process architecture is: {(Environment.Is64BitProcess ? "x64" : "x86")}");

            if (args.Length < 2 && !(args.Length == 1 && args[0] == "--coffee"))
            {
                Console.WriteLine(szUsage);
                return;
            }

            try
            {
                if (args[0] == "--coffee")
                {
                    Console.WriteLine(szCoffee);
                    return;
                }

                string szFilePath = args[1];
                if (!File.Exists(szFilePath))
                    fnLogError("File not found: " + szFilePath);

                byte[] abBytes = File.ReadAllBytes(szFilePath);
                //fnLogInfo("Base64: " + Convert.ToBase64String(abBytes));
                fnLogOK("Read file bytes successfully. Length: " + abBytes.Length.ToString());

                if (args[0] == "--x86")
                {
                    fnLogInfo("Action => x86 loading.");

                    if (Environment.Is64BitProcess)
                        throw new Exception($"The current process architecture is: {(Environment.Is64BitProcess ? "x64" : "x86")}");

                    x86PELoader pe = new x86PELoader(abBytes);
                    if (!pe.Is32Bit)
                        throw new Exception("This is not an x86 PE file.");

                    fnLogOK(string.Format("Preferred Load Address = {0}", pe.OptionalHeader.ImageBase.ToString("X4")));

                    fnDoX86Loading(pe);
                }
                else if (args[0] == "--x64")
                {
                    fnLogInfo("Action => x64 loading.");

                    if (!Environment.Is64BitProcess)
                        throw new Exception($"The current process architecture is: {(Environment.Is64BitProcess ? "x64" : "x86")}");

                    //Acknowledgement: https://github.com/S3cur3Th1sSh1t/Creds/blob/master/Csharp/PEloader.cs

                    x64PELoader pe = new x64PELoader(abBytes);
                    if (pe.Is32BitHeader)
                        throw new Exception("This is not an x64 PE file.");

                    fnLogOK($"Preferred Load Address = {pe.OptionalHeader64.ImageBase.ToString("X4")}");

                    fnDoX64Loading(pe);
                }
                else
                {
                    fnLogError("Unknown command: " + args[0]);
                }
            }
            catch (Exception ex)
            {
                fnLogError(ex.Message);
            }
        }

        static void fnDoX86Loading(x86PELoader pe)
        {
            IntPtr imageBase = NativeDeclarations.VirtualAlloc(
                        IntPtr.Zero,
                        pe.OptionalHeader.SizeOfImage,
                        NativeDeclarations.MEM_COMMIT | NativeDeclarations.MEM_RESERVE,
                        NativeDeclarations.PAGE_EXECUTE_READWRITE
                    );

            fnLogOK($"Allocated Space For {pe.OptionalHeader.SizeOfImage.ToString("X4")} at {imageBase.ToString("X4")}");

            //copy headers
            Marshal.Copy(pe.RawBytes, 0, imageBase, (int)pe.OptionalHeader.SizeOfHeaders);

            //copy sections
            foreach (var sec in pe.Sections)
            {
                IntPtr dest = IntPtr.Add(imageBase, (int)sec.VirtualAddress);
                Marshal.Copy(
                    pe.RawBytes,
                    (int)sec.PointerToRawData,
                    dest,
                    (int)sec.SizeOfRawData
                );
            }

            //relocation
            long delta = imageBase.ToInt64() - pe.OptionalHeader.ImageBase;
            if (delta != 0)
            {
                var dir1 = pe.OptionalHeader.BaseRelocationTable;
                if (dir1.Size == 0)
                    throw new Exception("Size is zero!");

                IntPtr relocBase = IntPtr.Add(imageBase, (int)dir1.VirtualAddress);
                int offset = 0;

                while (true)
                {
                    NativeDeclarations.IMAGE_BASE_RELOCATION block = Marshal.PtrToStructure<NativeDeclarations.IMAGE_BASE_RELOCATION>(IntPtr.Add(relocBase, offset));

                    if (block.SizeOfBlock == 0)
                        break;

                    int count = (int)((block.SizeOfBlock - 8) / 2);
                    IntPtr fixupBase = IntPtr.Add(imageBase, (int)block.VirtualAddress);

                    for (int i = 0; i < count; i++)
                    {
                        ushort value = (ushort)Marshal.ReadInt16(relocBase, offset + 8 + i * 2);

                        ushort type = (ushort)(value >> 12);
                        ushort rva = (ushort)(value & 0xFFF);

                        if (type == 0x3) //IMAGE_REL_BASED_HIGHLOW
                        {
                            IntPtr patch = IntPtr.Add(fixupBase, rva);
                            int original = Marshal.ReadInt32(patch);
                            Marshal.WriteInt32(patch, original + (int)delta);
                        }
                    }

                    offset += (int)block.SizeOfBlock;
                }
            }

            //imports
            var dir2 = pe.OptionalHeader.ImportTable;
            if (dir2.Size == 0)
                throw new Exception("Size is zero.");

            int descSize = Marshal.SizeOf<NativeDeclarations.IMAGE_IMPORT_DESCRIPTOR>();
            IntPtr descPtr = IntPtr.Add(imageBase, (int)dir2.VirtualAddress);

            while (true)
            {
                NativeDeclarations.IMAGE_IMPORT_DESCRIPTOR desc = Marshal.PtrToStructure<NativeDeclarations.IMAGE_IMPORT_DESCRIPTOR>(descPtr);

                if (desc.Name == 0) break;

                string dllName = Marshal.PtrToStringAnsi(IntPtr.Add(imageBase, (int)desc.Name));
                fnLogInfo("DLL: " + dllName);

                IntPtr hDll = NativeDeclarations.LoadLibrary(dllName);

                IntPtr thunkRef = IntPtr.Add(
                    imageBase,
                    (int)(desc.OriginalFirstThunk != 0 ? desc.OriginalFirstThunk : desc.FirstThunk)
                );

                IntPtr funcRef = IntPtr.Add(imageBase, (int)desc.FirstThunk);

                while (true)
                {
                    int thunkData = Marshal.ReadInt32(thunkRef);
                    if (thunkData == 0)
                        break;

                    IntPtr funcAddr;

                    if ((thunkData & 0x80000000) != 0)
                    {
                        //ordinal
                        funcAddr = NativeDeclarations.GetProcAddress(hDll, (IntPtr)(thunkData & 0xFFFF));
                    }
                    else
                    {
                        IntPtr namePtr = IntPtr.Add(imageBase, thunkData);
                        string name = Marshal.PtrToStringAnsi(IntPtr.Add(namePtr, 2));
                        funcAddr = NativeDeclarations.GetProcAddress(hDll, name);
                    }

                    Marshal.WriteInt32(funcRef, funcAddr.ToInt32());

                    thunkRef = IntPtr.Add(thunkRef, 4);
                    funcRef = IntPtr.Add(funcRef, 4);
                }

                descPtr = IntPtr.Add(descPtr, descSize);
            }

            //Jump to OEP.
            fnLogOK("Jump to OEP");
            IntPtr entry = IntPtr.Add(imageBase, (int)pe.OptionalHeader.AddressOfEntryPoint);
            IntPtr hThread = NativeDeclarations.CreateThread(IntPtr.Zero, 0, entry, IntPtr.Zero, 0, IntPtr.Zero);
            NativeDeclarations.WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
        
        static void fnDoX64Loading(x64PELoader pe)
        {
            IntPtr codebase = IntPtr.Zero;
            codebase = NativeDeclarations.VirtualAlloc(IntPtr.Zero, pe.OptionalHeader64.SizeOfImage, NativeDeclarations.MEM_COMMIT, NativeDeclarations.PAGE_EXECUTE_READWRITE);

            fnLogOK($"Allocated Space For {pe.OptionalHeader64.SizeOfImage.ToString("X4")} at {codebase.ToString("X4")}");

            fnLogInfo("Copying sections...");
            for (int i = 0; i < pe.FileHeader.NumberOfSections; i++)
            {
                IntPtr y = NativeDeclarations.VirtualAlloc(IntPtr.Add(codebase, (int)pe.ImageSectionHeaders[i].VirtualAddress), pe.ImageSectionHeaders[i].SizeOfRawData, NativeDeclarations.MEM_COMMIT, NativeDeclarations.PAGE_EXECUTE_READWRITE);
                Marshal.Copy(pe.RawBytes, (int)pe.ImageSectionHeaders[i].PointerToRawData, y, (int)pe.ImageSectionHeaders[i].SizeOfRawData);
                fnLogInfo(string.Format("Section {0}, Copied To {1}", new string(pe.ImageSectionHeaders[i].Name), y.ToString("X4")));
            }

            //Perform Base Relocation
            //Calculate Delta
            long currentbase = (long)codebase.ToInt64();
            long delta;

            delta = (long)(currentbase - (long)pe.OptionalHeader64.ImageBase);

            fnLogOK($"Delta = {delta.ToString("X4")}");

            //Modify Memory Based On Relocation Table

            fnLogInfo(pe.OptionalHeader64.BaseRelocationTable.VirtualAddress.ToString("X4"));
            fnLogInfo(pe.OptionalHeader64.BaseRelocationTable.Size.ToString("X4"));

            IntPtr relocationTable = (IntPtr.Add(codebase, (int)pe.OptionalHeader64.BaseRelocationTable.VirtualAddress));
            //Console.WriteLine(relocationTable.ToString("X4"));

            NativeDeclarations.IMAGE_BASE_RELOCATION relocationEntry = new NativeDeclarations.IMAGE_BASE_RELOCATION();
            relocationEntry = (NativeDeclarations.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(relocationTable, typeof(NativeDeclarations.IMAGE_BASE_RELOCATION));
            fnLogInfo(relocationEntry.VirtualAddress.ToString("X4"));
            fnLogInfo(relocationEntry.SizeOfBlock.ToString("X4"));

            int imageSizeOfBaseRelocation = Marshal.SizeOf(typeof(NativeDeclarations.IMAGE_BASE_RELOCATION));
            IntPtr nextEntry = relocationTable;
            int sizeofNextBlock = (int)relocationEntry.SizeOfBlock;
            IntPtr offset = relocationTable;

            while (true)
            {

                NativeDeclarations.IMAGE_BASE_RELOCATION relocationNextEntry = new NativeDeclarations.IMAGE_BASE_RELOCATION();
                IntPtr x = IntPtr.Add(relocationTable, sizeofNextBlock);
                relocationNextEntry = (NativeDeclarations.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(x, typeof(NativeDeclarations.IMAGE_BASE_RELOCATION));


                IntPtr dest = IntPtr.Add(codebase, (int)relocationEntry.VirtualAddress);

                fnLogInfo($"Section Has {(int)(relocationEntry.SizeOfBlock - imageSizeOfBaseRelocation) / 2} Entires");
                fnLogInfo($"Next Section Has {(int)(relocationNextEntry.SizeOfBlock - imageSizeOfBaseRelocation) / 2} Entires");

                for (int i = 0; i < (int)((relocationEntry.SizeOfBlock - imageSizeOfBaseRelocation) / 2); i++)
                {

                    IntPtr patchAddr;
                    UInt16 value = (UInt16)Marshal.ReadInt16(offset, 8 + (2 * i));

                    UInt16 type = (UInt16)(value >> 12);
                    UInt16 fixup = (UInt16)(value & 0xfff);

                    switch (type)
                    {
                        case 0x0:
                            break;
                        case 0xA:
                            patchAddr = IntPtr.Add(dest, fixup);
                            //Add Delta To Location.
                            long originalAddr = Marshal.ReadInt64(patchAddr);
                            Marshal.WriteInt64(patchAddr, originalAddr + delta);
                            break;
                    }

                }

                offset = IntPtr.Add(relocationTable, sizeofNextBlock);
                sizeofNextBlock += (int)relocationNextEntry.SizeOfBlock;
                relocationEntry = relocationNextEntry;

                nextEntry = IntPtr.Add(nextEntry, sizeofNextBlock);

                if (relocationNextEntry.SizeOfBlock == 0) break;
            }

            //Resolve Imports

            IntPtr z = IntPtr.Add(codebase, (int)pe.ImageSectionHeaders[1].VirtualAddress);
            IntPtr oa1 = IntPtr.Add(codebase, (int)pe.OptionalHeader64.ImportTable.VirtualAddress);
            int oa2 = Marshal.ReadInt32(IntPtr.Add(oa1, 16));

            //Get And Display Each DLL To Load
            for (int j = 0; j < 999; j++) //HardCoded Number of DLL's Do this Dynamically.
            {
                IntPtr a1 = IntPtr.Add(codebase, (20 * j) + (int)pe.OptionalHeader64.ImportTable.VirtualAddress);
                int entryLength = Marshal.ReadInt32(IntPtr.Add(a1, 16));
                IntPtr a2 = IntPtr.Add(codebase, (int)pe.ImageSectionHeaders[1].VirtualAddress + (entryLength - oa2)); //Need just last part? 
                IntPtr dllNamePTR = (IntPtr)(IntPtr.Add(codebase, +Marshal.ReadInt32(IntPtr.Add(a1, 12))));
                string DllName = Marshal.PtrToStringAnsi(dllNamePTR);
                if (DllName == "") { break; }

                IntPtr handle = NativeDeclarations.LoadLibrary(DllName);
                fnLogInfo("DLL: " + DllName);
                for (int k = 1; k < 9999; k++)
                {
                    IntPtr dllFuncNamePTR = (IntPtr.Add(codebase, +Marshal.ReadInt32(a2)));
                    string DllFuncName = Marshal.PtrToStringAnsi(IntPtr.Add(dllFuncNamePTR, 2));
                    //Console.WriteLine("Function {0}", DllFuncName);
                    IntPtr funcAddy = NativeDeclarations.GetProcAddress(handle, DllFuncName);
                    Marshal.WriteInt64(a2, (long)funcAddy);
                    a2 = IntPtr.Add(a2, 8);
                    if (DllFuncName == "") break;

                }
                //Console.ReadLine();
            }

            //Transfer Control To OEP
            fnLogOK("Jump to OEP");
            IntPtr threadStart = IntPtr.Add(codebase, (int)pe.OptionalHeader64.AddressOfEntryPoint);
            IntPtr hThread = NativeDeclarations.CreateThread(IntPtr.Zero, 0, threadStart, IntPtr.Zero, 0, IntPtr.Zero);
            NativeDeclarations.WaitForSingleObject(hThread, 0xFFFFFFFF);
        }

        static void fnLogOK(string szMsg)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("[+] ");
            Console.ResetColor();
            Console.WriteLine(szMsg);
        }

        static void fnLogInfo(string szMsg)
        {
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.Write("[*] ");
            Console.ResetColor();
            Console.WriteLine(szMsg);
        }

        static void fnLogError(string szMsg)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write("[-] ");
            Console.ResetColor();
            Console.WriteLine(szMsg);
        }
    }
}
