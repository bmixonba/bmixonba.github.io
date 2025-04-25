# VPN Reversing Case-study

In my first post, I will reverse engineer the VPN, VPN Monster to demonstrate some basic static reversing techniques.

## Background

### Reversing Tools and Setup

I like to perform analysis on a Linux-based machine. I am most familiar with the software installation and development process,
but this is not a hard requirement. For code analysis, I use a combination of Jadx, Ghidra, python and bash scripts, and miscellaneous Linux commands (e.g., `strings`, `sort`, `uniq`, etc.).

I will be installing the application onto a Google Pixel 7a device. The device is rooted using [Magisk](https://github.com/topjohnwu/Magisk).

I like to download the application onto the device either through Google Play or Tencent Mobile Manager if I'm looking at Chinese applications. VPNs are not avaiable in China and Google and Apple have largely blocked VPNs from download (see [appcensorship.com](https://appcensorship.org/) for more information).
### What is a VPN?


### Static Reverse Engineering

On of the first steps I take when reversing an unknown application is to identify interesting strings
in the code. My tool of choice for this is 
