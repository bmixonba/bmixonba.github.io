# Rooting Android

This post focuses on how to root an Android phone. I have done this a few times
now and forunately, the process gets easier each time.  I am rooting my phone
because I need to dump the routing rules and table for the [Linux Routing]()
post. The phone I'm rooting is an Google Pixel 7a. This is a bummer for apps
that use hardware-based attestation supported by Google's SafetyNet API because
they wont run on an unlocked/modified ROM.

The overview of what I will be doing is:

1. Unlock the bootloader
2. Extract the `init_boot` files
3. Patch `init_boot` 
4. Flash new `init_boot`

The hardware and software requirements are below.

## Hardware

* Pixel 7a
* Machine (Laptop) to attach to Pixel
* USB cable to link PC to Pixel

![Pixel7a]({{ site.url }}/img/blog/pixelImage.jpeg)

## Software

* Magisk
* adb

# Unlock the bootloader

The first thing you need to do is unlock the bootloader. This process 
will wipe your device storage, so backup anything you care about before
doing this.

1. Enable developer mode: Settings > About Phone > tap `Build Number` 7 times
2. Enable USB debugging and OEM Unlocking: Settings > System > Advanced > Developer Options
3. Link Pixel to PC
4. Unlock bootloader with adb

```bash
$ adb reboot bootloader 
$ fastboot flashing unlock # or fastboot oem unlock
```
Figure 1. Commands to run from machine 

5. Reboot: Press the power button
6. Enable USB debugging and OEM Unlocking: Settings > System > Advanced > Developer Options

# Extract the `init_boot` files

1. Get factory image for your device [link](https://developers.google.com/android/images).

![Factory Image2]({{ site.url }}/img/blog/pixel7aAboutphone2.png)
![Factory Image1]({{ site.url }}/img/blog/pixelFactoryImage.png)
![Factory Image2]({{ site.url }}/img/blog/pixelFactoryImage2.png)

2. Extract `init_boot` files from the extracted factory image.

![Extract Factory]({{ site.url }}/img/blog/extractFactoryImage1.png)

```bash
$ unzip image-lynx-bp1a.250305.019.zip
```
3. Copy `init_boot` files to device:

```bash
$ adb push init_boot.img sdcard
```

# Patch `init_boot` 

I already have Magisk on my phone, but if you need to, download the latest
release [(Magisk v29.0)](https://github.com/topjohnwu/Magisk/releases/tag/v29.0), and install it
with adb install:

```bash
$ adb install Magisk-v29.0.apk
```

2. Patch `init_boot.img`: Magisk-v29.0 > Install > "Select `init_boot.img` from sdcard" > Let's Go

3. Copy the file back to your machine 

```bash
$ adb pull /storage/emulated/0/Download/magisk_patched-29000_tQflw.img
```

# Flash new `init_boot`

1. Reboot into bootloader:

```bash
$ adb reboot bootloader
```

2. Flash the patched `init_boot.img` file
```bash
$ fastboot flash init_boot_a magisk_patched-29000_tQflw.img
$ fastboot flash init_boot_b magisk_patched-29000_tQflw.img
```

# Reboot

Reboot the device and you're good to go!
