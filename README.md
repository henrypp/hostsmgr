<h1 align="center">hostsmgr</h1>

<p align="center">
	<a href="https://github.com/henrypp/hostsmgr/releases"><img src="https://img.shields.io/github/v/release/henrypp/hostsmgr?style=flat-square&include_prereleases&label=version&fix" /></a>
	<a href="https://github.com/henrypp/hostsmgr/releases"><img src="https://img.shields.io/github/downloads/henrypp/hostsmgr/total.svg?style=flat-square&fix" /></a>
	<a href="https://github.com/henrypp/hostsmgr/issues"><img src="https://img.shields.io/github/issues-raw/henrypp/hostsmgr.svg?style=flat-square&label=issues" /></a>
	<a href="https://github.com/henrypp/hostsmgr/graphs/contributors"><img src="https://img.shields.io/github/contributors/henrypp/hostsmgr?style=flat-square" /></a>
	<a href="https://github.com/henrypp/hostsmgr/blob/master/LICENSE"><img src="https://img.shields.io/github/license/henrypp/hostsmgr?style=flat-square" /></a>
</p>

-------

<p align="center">
	<img src="https://www.henrypp.org/images/hostsmgr.png?fix" />
</p>

### Description:
Console tool for sysadmins and other peoples who need to autoupdate "hosts" file.

### Command line:
~~~
-path - output file location (def: ".\hosts")
-ip - ip address to be set as resolver (def: "0.0.0.0")
-os - new line format; "win", "linux" or "mac" (def: "win")
-nobackup  - do not create backup for output file (opt.)
-noresolve - do not set resolver, just generate hosts list (opt.)
-nocache - do not use cache files, load directly from internet (opt.)
~~~

### System requirements:
- Windows 8.1 and above operating system.
- [Visual C++ 2022 Redistributable package](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170)

### Donate:
- [Bitcoin](https://www.blockchain.com/btc/address/1LrRTXPsvHcQWCNZotA9RcwjsGcRghG96c) (BTC)
- [Ethereum](https://www.blockchain.com/explorer/addresses/eth/0xe2C84A62eb2a4EF154b19bec0c1c106734B95960) (ETC)
- [Paypal](https://paypal.me/henrypp) (USD)
- [Yandex Money](https://yoomoney.ru/to/4100115776040583) (RUB)

### GPG Signature:
Binaries have GPG signature simplewall.exe.sig in application folder.

- Public key: [pubkey.asc](https://raw.githubusercontent.com/henrypp/builder/master/pubkey.asc) ([pgpkeys.eu](https://pgpkeys.eu/pks/lookup?op=index&fingerprint=on&search=0x5635B5FD))
- Key ID: 0x5635B5FD
- Fingerprint: D985 2361 1524 AB29 BE73 30AC 2881 20A7 5635 B5FD

Website: [www.henrypp.org](https://www.henrypp.org)<br />
Support: support@henrypp.org<br />
<br />
(c) 2016-2022 Henry++
