# rabbitircd

RabbitIRCD is a fork of the now-defunct UnrealIRCd 3.4 tree, originated by
developers on the Weresource IRC network.  Compared to UnrealIRCd 3.2, it
features, amongst other things:

 * High performance evented I/O using kqueue and epoll;
 * A high level of backwards compatibility with UnrealIRCd 3.2 usermodes,
   channel modes and user-facing features;
 * Link compatibility with UnrealIRCd 3.2.10 or newer;
 * A native TS6-like protocol using unforgeable unique identifiers for
   servers and clients;
 * Full IRCv3.1 compliance;
 * An open development process driven by stakeholders.

Right now RabbitIRCD is solely distributed using Git on GitHub.  We may
decide to do code releases in the future.

## building rabbitircd

To build RabbitIRCd, run these commands:

    sh autogen.sh
    ./Config
    make

If you specified an alternative location during `./Config` you also need
to run `make install`.

## configuring rabbitircd

Copy doc/example.conf to your main RabbitIRCD directory and call it ircd.conf.
Then open it in your preferred editor and make whatever modifications you feel
are necessary.

## starting rabbitircd

Just type: `./rabbitircd start`.

Note that after booting the errors are usually logged to ircd.log,
so check that file if you have any problems.

Again, check the FAQ (and docs) if you have any problems starting rabbitircd.

## links

 * [IRC](irc://irc.weresource.org/#ircd)
 * [GitHub](http://github.com/rabbitircd/rabbitircd)
 * [Website](http://www.rabbitircd.net/)
