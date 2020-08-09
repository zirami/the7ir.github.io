---
title: Reversing CTF - Flare-On 2019 Challenegs
tags: [Reversing, dnspy, .NET, Android, DNS, CTF, x64dbg, IDA]
layout: post
---

FireEye recently announced the [7th annual Flare-On Challenge!](https://www.fireeye.com/blog/threat-research/2020/08/announcing-the-seventh-annual-flare-on-challenge.html) For those who are unaware, Flare-On is the Front Line Applied Research & Expertise ([FLARE](https://www.fireeye.com/blog/threat-research.html/category/etc/tags/fireeye-blog-tags/FLARE)) team's annual CTF-style challenge for all active and aspiring reverse engineers, malware analysts and security professionals. I first attempted Flare-on in 2019 and I'm looking forward to hopefully making it further in my second attempt. I decided to get some practice in before this year's challenge opens by re-attacking Flare-On 2019. I know that plenty of write-ups already exist for the challenges I'm documenting at this point. This post is just an attempt to make note of preparation and makes for a fun excuse to do some reversing challenges.

I'm using FireEye's [FLARE VM](https://github.com/fireeye/flare-vm) for these challenges. It comes with tons of useful tools for malware analysis and/or reverse engineering. I don't recall having to install additional tools for any of the few challenges I completed - with the exception of Android Studio to analyse and execute the .apk file from level 2.

## Level 1: Meme Cat Battlestation

Level 1 starts out nice and simple with an awesome theme. The challenge consists of a single file - MemeCatBattleStation.exe, accompanied by a helpful hint in Message.txt:

```
Welcome to the Sixth Flare-On Challenge! 

This is a simple game. Reverse engineer it to figure out what "weapon codes" you need to enter to defeat each of the two enemies and the victory screen will reveal the flag. Enter the flag here on this site to score and move on to the next level.

* This challenge is written in .NET. If you don't already have a favorite .NET reverse engineering tool I recommend dnSpy

** If you already solved the full version of this game at our booth at BlackHat  or the subsequent release on twitter, congratulations, enter the flag from the victory screen now to bypass this level.
```

A quick check with CFF explorer shows that we're definitely working with a 32bit .NET assembly. 
![Image](/assets/img/flare-on-2019/lvl_1_cff_explorer.PNG)

A .NET assembly has been compiled to managed code - specifically, Microsoft Intermediate Language (MSIL). It is then Just-In-Time (JIT)-compiled into machine code by the CLR when executed. MSIL can be easily decompiled to something that looks very close to the assembly's original source code. 

Here's what the application looks like when it runs. 
![Image](/assets/img/flare-on-2019/lvl_1_first_run.PNG)

I can quickly determine a couple of things by seeing what happens when it runs.
1. I need to find a 'Weapon Arming Code'
2. There are probably multiple 'Stages' that will need to be cleared to get the flag
3. The challenge creator's memes are dank

The tool [dnspy](https://github.com/0xd4d/dnSpy) allows for reverse engineering .NET assemblies, including debugging and decompiling them - and is already installed in FLARE VM. Dnspy shows that there are 3 WinForms in the assembly that I care about: 'Stage1Form', 'Stage2Form' and 'VictoryForm'. Stage1Form has a function called `FireButton_Click()` that checks the string typed by the user against  the string "RAINBOW". So that one was easy enough...
![Image](/assets/img/flare-on-2019/lvl_1_dnspy_stage_1.PNG)

Typing the correct weapon code gives me a cool cat rainbow lazer animation then executes the Stage2Form, which prompts for another weapon arming code. The relevant code for stage 2 is below. Once a weapon code is provided, each character of the code is XORd with 0x41 ('A') and compared to the char[] array declared at the bottom of the `isValidWeaponCode()` function. If this function resolves true, the victory animation timer is started and I should be given the flag...
![Image](/assets/img/flare-on-2019/lvl_1_dnspy_stage_2.PNG)

There are plenty of ways to transform this back into the plaintext weapon code. I chose to use CyberChef to escape the unicode characters (`\u00xx`) and perform the XOR function. Here's the result...
![Image](/assets/img/flare-on-2019/lvl_1_cyberchef_decode.PNG)

Plugging that in gives me the flag `Kitteh_save_galixy@flare-on.com` :)
![Image](/assets/img/flare-on-2019/lvl_1_flag.PNG)

## Level 2: Overlong

Level 2 is a 32bit Portable Executable accompanied by a text file that says:
```
The secret of this next challenge is cleverly hidden. However, with the right approach, finding the solution will not take an <b>overlong</b> amount of time.
```

Running the binary only gives me a small "Output" window suggesting that some 'encoding' occurs.
![Image](/assets/img/flare-on-2019/lvl_2_first_run.PNG)

From here, I found both static and dynamic analysis useful. For debugging Windows PE files, I normally use x32/x64dbg and my go-to for disassembly is IDA. First, opening the file in IDA and viewing the entry function shows that two functions being called. The second function is a call to MessageBoxA which is where our 'Output' window is being created. The first one takes three arguments:
  1. A memory address to an empty local buffer
  2. "offset unk_402008" (Blob of seemingly encoded data from offset 0x402008 in .rdata)
  3. The value 0x1c      

![Image](/assets/img/flare-on-2019/lvl_2_ida_start.PNG)

Now I know that whatever 'encoding' might be occurring must be happening in the function "sub_401160" so next, I check out what it does. To summarise - the function loops x times, where x is the 3rd argument passed to the function. By default this is the constant 0x1c. For each iteration of the loop, it performs some kind of encoding (I didn't bother fully trying to understand because in this case, I didn't need to) on a byte from the data passed in as argument 2 before writing that 'decoded' byte to the next spot in the buffer passed by address as the 3rd argument. 
![Image](/assets/img/flare-on-2019/lvl_2_ida_decode.png)

The number 0x1c (28 decimal) = the length of "I never broke the encoding: " with a trailing space. So, it seems like the function is only decoding the first 28 bytes of data and the flag should be in the remainder of the data! I can easily test this in a debugger by increasing that value 0x1C to see if the function decodes more bytes... Here's what that looks like in x32dbg:
![Image](/assets/img/flare-on-2019/lvl_2_x32dbg_edit.PNG)

Now if I run the program, it loops enough times to decode the rest of the flag!
![Image](/assets/img/flare-on-2019/lvl_2_x32dbg_flag.PNG)






