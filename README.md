# dotNetPELoader

When I was developing a fileless execution method for [DuplexSpy RAT](https://github.com/iss4cf0ng/DuplexSpyCS), I could hardly find a C#-based x86 PE loader.

Most existing implementations I found were x64-only, such as the one developed by [Casey Smith](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/Csharp/PEloader.cs). Therefore I decided to develop a x86 version C# based PE loader myself.

This console application allows you to load x86 or x64 PE file into memory.  
First, it reads the file bytes from the specified file path, then determines the architecture of both the loader and the target PE file.

An x64 PE cannot be loaded by an x86 loader, and vice versa.

# Usage
```
dotNetLoader.exe --x64 x64_file.exe
dotNetLoader.exe --x86 x86_file.exe
dotNetLoader.exe --coffee
```
![](https://github.com/iss4cf0ng/dotNetPELoader/blob/main/screenshots/hello.png)

# Demonstration
## x64 - Loading an x64 mimikatz:
![](https://github.com/iss4cf0ng/dotNetPELoader/blob/main/screenshots/anycpu.png)


If you try to load an x86 PE while the loader is an x64 loader, an exception will be thrown:
```
> dotNetPELoader.exe --x86 minikatz.exe
```
![](https://github.com/iss4cf0ng/dotNetPELoader/blob/main/screenshots/x64.1.png)

```
> dotNetPELoader.exe --x86 minikatz.exe
```
![](https://github.com/iss4cf0ng/dotNetPELoader/blob/main/screenshots/x64.3.png)

![](https://github.com/iss4cf0ng/dotNetPELoader/blob/main/screenshots/x64.3.png)

## x86 - Loading an x86 mimikatz:
![](https://github.com/iss4cf0ng/dotNetPELoader/blob/main/screenshots/x86_cpu.png)

```
> dotNetPELoader.exe --x86 minikatz.exe
```
![](https://github.com/iss4cf0ng/dotNetPELoader/blob/main/screenshots/x86.1.png)

![](https://github.com/iss4cf0ng/dotNetPELoader/blob/main/screenshots/x86.2.png)
