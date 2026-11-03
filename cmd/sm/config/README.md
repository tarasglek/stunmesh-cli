`make build NODE=<node>` copies the node's public `node.json` here to be
compiled into the binary. It is per site and git ignores it; this file
keeps the directory, so the package builds from a fresh clone and reports
a missing config at run time instead of failing to compile.
