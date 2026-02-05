# dotNetPELoader
A C# PE loader for both x64 and x86 PE file.

Recently, when I was developing a fileless execution method for [DuplexSpy RAT](https://github.com/iss4cf0ng/DuplexSpyCS), I could hardly find a C#-based x86 PE loader.  
Most existing implementations I found were x64-only, such as the one developed by [Casey Smith](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/Csharp/PEloader.cs)
.
Therefore, I decided to develop a C#-based x86 PE loader myself.

This console application allows you to load either x86 or x64 PE files into memory.
First, it reads the file bytes from the specified file path, then determines the architecture of both the loader and the target PE file.

An x64 PE cannot be loaded by an x86 loader, and vice versa.

<p align="center">
<img src="https://iss4cf0ng.github.io/images/meme/mika_cute.jpg" width="300">
</p>

# Usage
```
dotNetPELoader.exe --x64 x64_file.exe
dotNetPELoader.exe --x86 x86_file.exe
dotNetPELoader.exe --coffee
```

![](https://github.com/iss4cf0ng/dotNetPELoader/blob/main/screenshots/hello.png)

# Demonstration
## x64 - mimikatz
![](https://github.com/iss4cf0ng/dotNetPELoader/tree/main/screenshots/anycpu.png)
```
dotNetPELoader.exe --x64 mimikatz
```
If you try to load an x86 PE while the loader is an x64 loader, an exception will be thrown:

![](https://github.com/iss4cf0ng/dotNetPELoader/blob/main/screenshots/x64.1.png)

![](https://github.com/iss4cf0ng/dotNetPELoader/blob/main/screenshots/x64.2.png)

![](https://github.com/iss4cf0ng/dotNetPELoader/blob/main/screenshots/x64.3.png)

## x86 - mimikatz
```
dotNetPELoader.exe --x86 mimikatz
```

![](https://github.com/iss4cf0ng/dotNetPELoader/blob/main/screenshots/x86.1.png)

![](https://github.com/iss4cf0ng/dotNetPELoader/blob/main/screenshots/x86.2.png)
