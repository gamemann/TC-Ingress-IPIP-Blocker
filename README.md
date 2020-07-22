# TC Ingress IPIP Blocker
## Description
A simple TC BPF program that attaches to the ingress filter and blocks any IPs stored in the `/etc/ipipblock/list.conf` file. This program checks the source IP of the inner IP header.

## Usage
Usage is as follows:

```
./ipipblock <interface>
```

Where `<interface>` is the interface incoming IPIP packets enter.

## Building
You may use `make` to build this project. For example:

```
make && sudo make install
```

**Note** - Clang and LLVM are required to build this project.

## Credits
* [Christian Deacon](https://www.linkedin.com/in/christian-deacon-902042186/) - Creator