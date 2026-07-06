# LocalSend CLI

> **NOTE:** The project was vibecoded using Kimi K2.6, the intent was to use this in my Quickshell setup
> 
> Other similar projects either did not work for me or had quirks which made them unusable in my case

## Install

```
git clone https://codeberg.org/nikkoxd/localsend-cli.git
cd localsend-cli
make install
```

## Basic usage

Discover devices on the network:

```
localsend-cli discover [--json] [--timeout <duration>]
```

Use flag `--json` to print the info about discovered devices into stdout as JSON.

Send files to a device:

```
localsend-cli send [--json] [--to <alias|ip:port>] [files...]
```

The CLI will auto-discover a device if one was not specified with the flag `--to`.

Use flag `--json` to print the result into stdout as JSON.

Start a server to receive files:

```
localsend-cli receive
```

Receiving files will print out a prompt, writing yes/no into stdin will accept/decline them.