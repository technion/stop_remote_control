# stop\_remote\_control
This project aims to assist organisations in completely removing Remote Control applications from their environment. Obvious decisions should be involved around allowing any specific product an organisation actually uses, however a long history of tech support scams and "hands on keyboard" compromises involve these legitimate products. As they are legitimate products, they will never be blocked by common EDR products by default. This repository aims to assist in changing that.

## sources
Original downloads of executables. We may only keep the latest versions here, but historic blocking information will be retained.

## certificates
Exports of signing certificates. These are expected to be the most likely useful content. Microsoft Defender for example supports custom certicate IOCs as per this guide: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/indicator-certificates?view=o365-worldwide

## hashes
Known file hashes. These are expected to be the least reliable option due to moving releases, however in some cases they may be the most suitable for your chosen EDR.

## Yara rules
Rules for use with a yara engine

