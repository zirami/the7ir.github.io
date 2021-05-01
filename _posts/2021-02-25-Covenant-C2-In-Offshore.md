---
title: Using the Covenant C2 Framework in Hack The Box Pro Labs 
tags: [C2, av-evasion, AMSI, .NET, lateral-movement, HTB]
layout: post
---

![Covenant Logo](/assets/img/covenant-offshore/covenant_logo.png)

# Using Covenant C2 Framework in the Hack The Box Pro Labs

## Summary

I've been interested in exploring .NET tooling for a while now, so I decided to give the [Covenant C2 Framework](https://github.com/cobbr/Covenant) by [Cobbr](https://cobbr.io/) a run for its money! This post will detail my use of Covenant within the Hack [The Box Pro Lab: Offshore](https://app.hackthebox.eu/prolabs/overview/2), including:
- A quick overview of Covenant
- Launching grunts - evading antivirus
- Launching grunts - bypassing AMSI
- Setting up cloud-based C2 infrastructure for HTB
- A quick overview of Offshore
- Playing with Grunts in the labs!

This post **won't** cover:
- Spoilers from the lab
