<!--
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
-->

<!--
    Copyright 2019 Joyent, Inc.
-->

This repository is part of the Joyent Triton project. See the [contribution
guidelines](https://github.com/joyent/triton/blob/master/CONTRIBUTING.md)
and general documentation at the main [Triton
project](https://github.com/joyent/triton) page.

# Binder Load Balancer (mname-balancer)

This program is a simple DNS load balancer built to work with the Node-based
[node-mname][mname] DNS server library, as used in the [Binder][binder] service
discovery server.  A listen socket is established for both TCP and UDP on the
nominated DNS server port to receive requests from remote peers.  A pool of
connections to backend server processes is maintained via local sockets
(`AF_UNIX`).

```
 +----------+                         :53 ####################
 | DNS      | ------- DNS requests =====> #  mname-balancer  #
 | Client 1 |         /     /             #                  #
 +----------+        /     /              ####################
                    /     /                       |||
 +----------+      /     /                        |||
 | DNS      | ----/     /                /var/run/binder/sockets/...
 | Client 2 |          /                        /  |  \   (UNIX sockets)
 +----------+         /                        /   |   \
     .               /                        /    |    \
     .              /                   ./5301  ./5302  ./5303
     .             /                        /      |      \
     .            /                        v       v       v
 +----------+    /                **********  **********  **********
 | DNS      | --/                 * Binder *  * Binder *  * Binder *
 | Client N |                     **********  **********  **********
 +----------+
```

## Program Structure

The program is broken up into different subsystems, each in a separate file.
Each file has a comment which describes the particular subsystem in some
detail.  Of particular note is the description of the protocol that forms an
interface between this program and [node-mname][mname], which appears in
`backends.c`.

### Subsystems

* `main.c`: program entry point, option parsing, initialisation, etc.

* `backend.c`: enumeration of backend Binder processes, establishment
  of a persistent connection with each backend, liveness checking,
  detection of faults, etc.

* `remotes.c`: maintaining the association between remote hosts and
  their assigned backend.

* `timeouts.c`: a lightweight, coarse-grained timeout mechanism used
  by other subsystems to schedule future execution of maintenance
  routines (e.g., socket data timeout); roughly analogous to
  `setTimeout()` in JavaScript.

* `udp_proxy.c`: establishes a UDP socket on the DNS port, and relays
  DNS packets between remote hosts and backends via the persistent
  connections maintained in `backend.c`.

* `tcp_proxy.c`: establishes a TCP listen socket on the DNS port,
  and proxies any incoming TCP connection to the appropriate
  backend.

### Dependencies

The software depends on several other modules, included under the `deps/` tree.
In some cases these dependencies are included as a submodule when an
appropriate upstream git repository exists.  If modifications have been made,
or if no such upstream yet exists, a copy has been made.  Current dependencies
include:

* `deps/illumos-bunyan` (copy): a private fork of the illumos [Bunyan][bunyan]
  logging library, with some minor modifications

* `deps/illumos-list` (submodule): illumos [list_create(9F)][list_create]
  linked list routines

* `deps/libcbuf` (submodule): buffer and buffer queue management routines

* `deps/libcloop` (internal, no upstream yet): event ports-based event loop

## Running

The software has no persistent configuration file but does accept a number of
command-line arguments.  It is expected that the correct set of arguments
will be passed by the service supervisor; e.g., the [binder-balancer][smf]
service shipped with Binder.  Supported options include:

* `-b IP_ADDRESS`: the IP interface address on which to listen for DNS packets
  (default `0.0.0.0`, or all interfaces)

* `-p PORT`: the port number to use when listening for both TCP and UDP DNS
  packets (default `53`)

* `-l LOG_LEVEL`: the [Bunyan][bunyan] log level (default `info`; valid
  levels are `trace`, `debug`, `info`, `warn`, `error`, or `fatal`)

* `-s BACKEND_PATH`: the directory where `AF_UNIX` sockets for Binder
  backends will be created (required; no default)

A log level string may also be passed in the `LOG_LEVEL` environment variable.
If that variable is set, it will override a `-l` value passed on the command
line.

## Building

This software is written for illumos systems; in particular, SmartOS.

### Development

For development purposes it is possible to build this repository directly.
In a SmartOS zone, install appropriate build tools:

* C compiler and GNU make; e.g., `pkgin install build-essential`
* CTFCONVERT set appropriately

With those tools installed, you should be able to build the balancer program
with `gmake`.  The resultant binary will be called `bbal`.

### Release

Release builds of the software are driven through the `Makefile` in the
[Binder][binder] project, where this repository is included as a git submodule.
The `Makefile` in this project allows the consumer to override several
key variables when building as part of a larger workspace:

* `PROG` should be set to the fully qualified path of the target
  executable

* `OBJ_DIR` can be set to a temporary directory, ideally one specific
  to the load balancer build so that there are no conflicts; this
  allows the submodule clone to remain pristine during the build

* `CTFCONVERT` must be set to the path of the `ctfconvert` program

## Debugging

Built binaries include CTF type information, allowing an engineer to inspect C
objects in either the running program or in a core file.  Most subsystems
declare some set of "anchor" objects as globals, which are easy to locate in
the debugger.

For instance, the set of backends is stored in an AVL tree (see `backends.c`):

```
[root@ad443830 (nameservice) ~]$ pgrep -fl balancer
37229 /opt/smartdc/binder/lib/balancer -s /var/run/binder/sockets

[root@ad443830 (nameservice) ~]$ mdb -o nostop -p 37229
Loading modules: [ libumem.so.1 libavl.so.1 libnvpair.so.1 ]
> g_backends::walk avl | ::print backend_t
{
    be_node = {
        avl_child = [ 0, 0 ]
        avl_parent = 0
        avl_child_index = 0
        avl_balance = 0
    }
    be_node_by_path = {
        avl_child = [ 0, 0 ]
        avl_parent = 0
        avl_child_index = 0
        avl_balance = 0
    }
    be_id = 0x14b5
    be_path = 0x80a6fb0 "/var/run/binder/sockets/5301"
    be_loop = 0x80b4fa0
    be_conn = 0x80c3dc8
    be_ok = 0x1 (B_TRUE)
    be_reconnect = 0 (0)
    be_heartbeat_outstanding = 0 (0)
    be_removed = 0 (0)
    be_remotes = 0x1f
    be_connect_timeout = 0x80aff88
    be_heartbeat_timeout = 0x80aff08
    be_reconnect_timeout = 0x80aff48
    be_reconnect_delay = 0x1
    be_log = 0x80a2540
    be_stat_conn_start = 0x1
    be_stat_conn_error = 0
    be_stat_udp = 0x423e33
    be_stat_tcp = 0
}
```

Or the list of currently scheduled timeouts (see `timeouts.c`):

```
> g_timeouts::walk avl | ::print timeout_t
{
    to_node = {
        avl_child = [ 0, 0 ]
        avl_parent = 0
        avl_child_index = 0
        avl_balance = 0
    }
    to_id = 0x3
    to_scheduled_at = 0x317ef1a176887
    to_run_at = 0
    to_expiry = 0x317f0441d5a87
    to_func = backend_send_heartbeat
    to_arg = 0x80c2f48
    to_active = 0x1 (B_TRUE)
}
```

Or the list of known remote hosts and their current backend (see `remotes.c`):

```
> g_remotes::walk avl | ::printf "%12p %12I -> %d\n" remote_t . rem_addr.S_un.S_addr rem_backend
     80b0cd0   10.77.77.5 -> 5301
     80b0250  10.77.77.64 -> 5301
     80b0670  10.77.77.65 -> 5301
     80b0af0  10.77.77.66 -> 5301
     80b07f0  10.77.77.67 -> 5301
     80b0a90  10.77.77.68 -> 5301
     80b0c70  10.77.77.69 -> 5301
     80b0610  10.77.77.70 -> 5301
     80b0c10  10.77.77.71 -> 5301
     80b0490  10.77.77.72 -> 5301
...
```

The Binder project ships a tool, [`balstat`][balstat], which presents this
debugging information in a form that is often useful to operators.


<!-- References -->
[mname]: https://github.com/joyent/node-mname
[binder]: https://github.com/joyent/binder
[smf]: https://github.com/joyent/binder/blob/0a065742b61417a91050350075b7f8f4bb943e86/smf/manifests/binder-balancer.xml.in#L39-L46
[bunyan]: https://github.com/trentm/node-bunyan
[list_create]: https://illumos.org/man/9F/list_create
[balstat]: https://github.com/joyent/binder/blob/master/bin/balstat
