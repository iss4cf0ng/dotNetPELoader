# dotNetPELoader

When I was developing a fileless execution method for [DuplexSpy RAT](https://github.com/iss4cf0ng/DuplexSpyCS), I hardly find a C# based x86 version PE loader.  
I have only found a x64 version which was developed by [Casey Smith](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/Csharp/PEloader.cs). Therefore I decided to develop a x86 version C# based PE loader.

This console application allows you to load x86 or x64 PE file into memory.  
Firsly, it reads file bytes of specified file path, it then determines the architecture of loader and the PE file.   
A x64 PE cannot be loaded through a x64 loader and vice versa.

# Usage
```
dotNetLoader.exe --x64 x64_file.exe
dotNetLoader.exe --x86 x86_file.exe
dotNetLoader.exe --coffee
```

