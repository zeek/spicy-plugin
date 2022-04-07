
# Spicy Plugin for Zeek

This repository provides a [Zeek](https://github.com/zeek/zeek)
package that adds [Spicy](https://github.com/zeek/spicy) support to
Zeek through a plugin. After installing this package, you can then
load Spicy-based protocol and file analyzers, such as those coming
with the [Spicy Analyzers](https://github.com/zeek/spicy-analyzers)
package.

## Prerequisites

In addition to Zeek, you will first need to install Spicy. Please
follow [its instructions](https://docs.zeek.org/projects/spicy/en/latest/installation.html).
Ensure that the Spicy toolchain is in your ``PATH``. For example, with
Spicy installed to `/opt/spicy` and using `bash`:

    export PATH=/opt/spicy/bin:$PATH

Now `which` should be able to find `spicy-config`:

    # which spicy-config
    /opt/spicy/bin/spicy-config

Please also [install and
configure](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)
the Zeek package manager.

## Installation

### Install through package manager

The easiest, and recommended, way to install the Spicy plugin is
through the Zeek package manager:

    # zkg install zeek/spicy-plugin

This will pull down the package, compile and test the plugin, and then
install and activate it. To check that the plugin becomes available,
run `zeek -N Zeek::Spicy` afterwards, it should show output like
this:

    # zeek -NN Zeek::Spicy
    Zeek::Spicy - Support for Spicy parsers (*.spicy, *.evt, *.hlto) (dynamic, version x.y.z)

If you want to develop your own Spicy analyzers for Zeek, you will
need a tool that comes with the plugin: ``spicyz``. Please see the
[Spicy manual](https://docs.zeek.org/projects/spicy/en/latest/zeek.html#zeek_spicyz)
on how to make `spicyz` show up in your `PATH` after the plugin got
installed.

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
    Zeek::Spicy - Support for Spicy parsers (*.spicy, *.evt, *.hlto) (dynamic, version x.y.z)

You will also find `spicyz` in `${prefix}/bin` now.

By default, the plugin will search for precompiled `*.hlto` files in
`<prefix>/lib/zeek-spicy/modules`. You change that path by setting
`ZEEK_SPICY_MODULE_DIR` through CMake.

## Documentation

The plugin's documentation is [part of the Spicy
manual](https://docs.zeek.org/projects/spicy/en/latest/zeek.html).

## License

Just like Spicy, the plugin is open source and released under a BSD license.
