# Zeek Package Template (Beta!)

This is the default template for the [Zeek](https://github.com/zeek/zeek)
[package manager](https://github.com/zeek/package-manager). If your `zkg`
supports the `create` command, you can use this template to bootstrap
new Zeek packages.

## Features

By default, the template provides a plain Zeek package with a
functional btest setup. You can add the following optional features:

- `plugin`: this feature adds plugin support to the new package. It
  includes a minimal, functional plugin that Zeek loads and shows in its
  `-N` output, with a testcase.

  The plugin's Zeek and C++ sources reside in the package's `plugin`
  folder. This is a departure from past plugin layouts that helps
  avoid subtle script-loading problems we've occasionally encountered
  in the past. You'll find the plugin-level Zeek scripts (such as
  `__preload__.zeek`) in `plugin/scripts`, and the package-level ones
  (where you'll define log streams, handle runtime events, etc)
  directly in the toplevel `scripts` folder.

- `github-ci`: this feature adds two
  [Github Action workflows](https://docs.github.com/en/actions).
  The first tests the package across our triplet of supported
  [binary packages](https://github.com/zeek/zeek/wiki/Binary-Packages) (the
  latest nightly Zeek build, the latest release, and the latest LTS
  release) for pushes and pull requests. The second is a daily test
  of the newest package version against the Zeek nightly build.
  Both rely on our
  [Github action for testing Zeek packages](https://github.com/zeek/action-zkg-install).

All packages require Zeek 4 or newer.

## User variables

Zeek package templates support `zkg`'s user variables for
parameterization. This template is currently quite basic and only
requires two input variables:

- `name`: a name for the new package, such as `MyPackage`

- `namespace`: a namespace for the package, such as `MyOrg`. This is
  required only when using the plugin feature.

## Status

Note that `zkg`'s template support is a beta feature and some
functionality is still undergoing changes. Early feedback, feature
requests, and bug reports are all very welcome.
