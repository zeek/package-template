# Zeek Package Template

[![Zeek tests](https://github.com/zeek/package-template/actions/workflows/check.yml/badge.svg)](https://github.com/zeek/package-template/actions/workflows/check.yml)

This is the default template for the [Zeek](https://github.com/zeek/zeek)
[package manager](https://github.com/zeek/package-manager). If your `zkg`
supports the `create` command, you can use this template to bootstrap
new Zeek packages.

## Features

By default, the template provides a plain Zeek package with a
functional btest setup. You can add the following optional features:

- `plugin` adds plugin support to the new package. It
  includes a minimal, functional plugin that Zeek loads and shows in its
  `-N` output, with a testcase.

  The plugin's Zeek and C++ sources reside in the package's `plugin`
  folder. This is a departure from past plugin layouts that helps
  avoid subtle script-loading problems we've occasionally encountered
  in the past. You'll find the plugin-level Zeek scripts (such as
  `__preload__.zeek`) in `plugin/scripts`, and the package-level ones
  (where you'll define log streams, handle runtime events, etc)
  directly in the toplevel `scripts` folder.

- `spicy-file-analyzer`/`spicy-packet-analyzer`/`spicy-protocol-analyzer`
  each add a Spicy analyzer to the package: either a file analyzer, or
  a packet analyzer, or a protocol analyzer, respectively. They all
  expect to receive one common user variable: `analyzer` specifies the
  name of the analyzer (e.g., `HTTP`). Packet and file analyzers
  further rely on the name of a top-level Spicy `unit` where to start
  parsing their format. Protocol analyzers expect two separate units
  instead, one for each direction (`unit_orig` and `unit_resp`; these
  may be the same), as well as a `protocol` to specify whether it's a
  TCP- or UDP-based protocol that's to be parsed. For all analyzers,
  make sure to read through the generated package for remaining TODOs.
  These features and `plugin` are mutually exclusive. For Zeek 5.0 and
  newer, the resulting package will work immediately; for older Zeek
  versions please ensure you have the
  [spicy-plugin](https://github.com/zeek/spicy-plugin) Zeek package
  installed.

- `license` lets you choose a license for your package.  Available
  choices include the Apache 2.0, BSD 2- and 3-clause, MIT, and Mozilla 2.0
  licenses. You're free to use others; these are just the ones most commonly
  used for Zeek packages.  The resulting license gets placed into `COPYING` at
  the package's toplevel.

- `github-ci` adds two
  [Github Action workflows](https://docs.github.com/en/actions).
  The first tests the package across our triplet of supported
  [binary packages](https://github.com/zeek/zeek/wiki/Binary-Packages) (the
  latest nightly Zeek build, the latest release, and the latest LTS
  release) for pushes and pull requests. The second is a daily test
  of the newest package version against the Zeek nightly build.
  Both rely on our
  [Github action for testing Zeek packages](https://github.com/zeek/action-zkg-install).

All packages require Zeek 4 or newer, and Zeek 5 is recommended.

## Example

To create scripting-only Zeek package with a 3-clause BSD license:

```
$ zkg create --features license --packagedir newpackage
"package-template" requires a "name" value (the name of the package, e.g. "FooBar"):
name: FooBar
"package-template" requires a "author" value (your name and email address):
author: My Name <my.name@example.com>
"package-template" requires a "license" value (one of apache, bsd-2, bsd-3, mit, mpl-2):
license: bsd-3

$ cd newpackage
$ ls
COPYING  README  scripts/  testing/  zkg.meta
```

## Status

Note that `zkg`'s template support is a beta feature and some
functionality is still undergoing changes. Early feedback, feature
requests, and bug reports are all very welcome.
