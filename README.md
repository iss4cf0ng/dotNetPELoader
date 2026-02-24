# dotNetPELoader
## Security Notice
Recently, I discovered an unofficial modified version of this project being redistributed outside of this repository.

After reviewing the files, I identified additional hidden components and script-loading behavior that do **NOT** exist in the official source code.

Please be aware:

- The unofficial distribution includes extra executable and script-loading elements that are **NOT** part of the original source code.
- The official releases of this project are published **ONLY in this repository**.
- Official releases do **NOT** contain additional batch files, hidden loaders, or embedded script components.

I am not affiliated with any third-party redistribution of this project.

For safety reasons:

- If you encounter repackaged builds containing unexpected executables or loaders, do not run them.
- Only download releases directly from this repository.
- Review the source code before building whenever possible.

<p align="center">
<img src="https://iss4cf0ng.github.io/images/meme/mika_rollcake_hit.png" width=300>
</p>

## Introduction
A C# PE loader for x64 and x86 PE files.

Recently, when I was developing a fileless execution method for [DuplexSpy RAT](https://github.com/iss4cf0ng/DuplexSpyCS) version 2, I could hardly find a C#-based x86 PE loader.  
Most existing implementations I found were x64-only, such as the one developed by [Casey Smith](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/Csharp/PEloader.cs)
.
Therefore, I decided to develop a C#-based x86 PE loader myself.

This console application allows you to load either x86 or x64 PE files into memory.
First, it reads the file bytes from the specified file path, then determines the architecture of both the loader and the target PE file.

An x64 PE cannot be loaded by an x86 loader, and vice versa.

## Features
- Load **x86 PE in x86 process**
- Load **x64 PE in x64 process**
- Handles relocation and import resolving
- Fully written in C#

If you find this project useful, a ⭐ would be appreciated.
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

![](https://github.com/iss4cf0ng/dotNetPELoader/blob/main/screenshots/anycpu.png)

If you try to load an x86 PE while the loader is an x64 loader, an exception will be thrown:
```
dotNetPELoader.exe --x64 mimikatz
```

![](https://github.com/iss4cf0ng/dotNetPELoader/blob/main/screenshots/x64.1.png)

![](https://github.com/iss4cf0ng/dotNetPELoader/blob/main/screenshots/x64.2.png)

![](https://github.com/iss4cf0ng/dotNetPELoader/blob/main/screenshots/x64.3.png)

## x86 - mimikatz

![](https://github.com/iss4cf0ng/dotNetPELoader/blob/main/screenshots/x86_cpu.png)

```
dotNetPELoader.exe --x86 mimikatz
```

![](https://github.com/iss4cf0ng/dotNetPELoader/blob/main/screenshots/x86.1.png)

![](https://github.com/iss4cf0ng/dotNetPELoader/blob/main/screenshots/x86.2.png)
