# TC Ingress IPIP Blocker
## Description
A simple TC BPF program that attaches to the ingress filter and blocks any IPs stored in the specified file (default is `/etc/IPIPBlock/list.conf`). This program checks the source IP of the inner IP header.

## Usage
Usage is as follows:

```
./IPIPBlock --dev <interface> --list <file> --time <updatetime> [--help]
```

Where `<interface>` is the interface incoming IPIP packets enter and `<file>` is the file that contains all the IPs to blacklist. The default interface is `ens18` and the default file is `/etc/IPIPBlock/list.conf`. The `<updatetime>` value indicates how often to update the blacklist map from the local file.

**Note** - Comments or characters after an IP in the blacklist file should be fine. I've tested this and there were no changes in behavior compared to nothing being added after an IP per line.

For example, the following works:

```
192.168.90.1
80.4.23.12 # Malicious host (not actually) and this will still block regardless of the comment.
garbage # This never gets processed from what I've seen and is just treated as a garbage value.
```

## Building
You may use `git` and `make` to build this project. For example:

```
git --recursive https://github.com/gamemann/TC-Ingress-IPIP-Blocker.git
cd TC-Ingress-IPIP-Blocker/
make && sudo make install
```

**Note** - Clang and LLVM are required to build this project.

## Credits
* [Christian Deacon](https://www.linkedin.com/in/christian-deacon-902042186/) - Creator