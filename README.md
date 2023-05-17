
***Note: This plugin is no longer needed with Zeek >= 6.0, which comes
with Spicy support built in. All new development now happens in Zeek
directly. This repository will still be receiving important bugfixes
for the time being, but will eventually be shut down.***

# Spicy Plugin for Zeek

This repository provides a [Zeek](https://github.com/zeek/zeek)
package that adds [Spicy](https://github.com/zeek/spicy) support to
Zeek through a plugin. Once installed, your Zeek will be able to
load Spicy-based protocol and file analyzers, such as those coming
with the [Spicy Analyzers](https://github.com/zeek/spicy-analyzers)
package.

Both this plugin and Spicy itself now ship with Zeek by default, so
chances are that you already have Spicy support in place if you are
using Zeek >= 5.0.

## Prerequisites

If not using Zeek's built-in version of the plugin, you will first
need to install Spicy. Please follow [its
instructions](https://docs.zeek.org/projects/spicy/en/latest/installation.html).
Ensure that the Spicy toolchain is in your `PATH`. For example, with
Spicy installed to `/opt/spicy` and using `bash`:

    export PATH=/opt/spicy/bin:$PATH

Now `which` should be able to find `spicy-config`:

    # which spicy-config
    /opt/spicy/bin/spicy-config

Please also [install and
configure](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)
the Zeek package manager.

## Installation

### Use Zeek's built-in version

Zeek includes both Spicy and this plugin by default since version 5.0.
To confirm that you have it available, run `zeek -N Zeek::Spicy`, it
should show output like this:

    # zeek -N Zeek::Spicy
    Zeek::Spicy - Support for Spicy parsers (*.hlto) (built-in)

Assuming that's the case, you should also find the plugin's
compilation tool `spicyz` at the same place as the Zeek executable:

    # which spicyz
    /usr/local/zeek/bin/spicyz

If you do not want to use the Spicy plugin that's built into Zeek for
some reason (e.g., because you'd like to try a new version of the
plugin or Spicy), you can build Zeek with `--disable-spicy` and then
follow the instructions below for installation through the package
manager or from source.

### Install through package manager

If not using Zeek's built-in Spicy support, the recommended way to
install the Spicy plugin is through the Zeek package manager:

    # zkg install zeek/spicy-plugin

This will pull down the package, compile and test the plugin, and then
install and activate it. To check that the plugin has become available,
run `zeek -N Zeek::Spicy` afterwards, it should show output like
this:

    # zeek -N Zeek::Spicy
    Zeek::Spicy - Support for Spicy parsers (*.hlto) (dynamic, version x.y.z)

The compilation tool `spicyz` comes with the package as well, and
should show up in your `PATH` after installation. If that's not the
case, please see the [Spicy
manual](https://docs.zeek.org/projects/spicy/en/latest/zeek.html#zeek_spicyz)
on how to locate it (you might be using an older version of *zkg*
still).

### Install manually

You can also install the plugin through normal CMake means. After
cloning this repository, make sure that the Spicy tools are in your
`PATH`, per above. Then build the plugin like this:

    # (mkdir build && cd build && cmake -DCMAKE_INSTALL_PREFIX=/opt/spicy .. && make -j)

The tests should now pass:

    # make -C tests

You can then install the plugin (which you may need to do as root so
that you can write to the Zeek plugin directory):

    # make -C build install

Zeek should now show it:

    # zeek -N Zeek::Spicy
    Zeek::Spicy - Support for Spicy parsers (*.hlto) (dynamic, version x.y.z)

You will also find `spicyz` in `${prefix}/bin` now.

By default, the plugin will search for precompiled `*.hlto` files in
`<prefix>/lib/zeek-spicy/modules`. You change that path by setting
`ZEEK_SPICY_MODULE_DIR` through CMake.

## Documentation

The plugin's documentation is [part of the Spicy
manual](https://docs.zeek.org/projects/spicy/en/latest/zeek.html).

## License

Just like Spicy, the plugin is open source and released under a BSD license.
