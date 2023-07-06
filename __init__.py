"""The driver for this Zeek package template. See the documentation at

https://docs.zeek.org/projects/package-manager/en/stable/zkg.html#create
https://docs.zeek.org/projects/package-manager/en/stable/api/template.html

for details.
"""
from datetime import date
import glob
import os
import textwrap

import git

import zeekpkg.template
import zeekpkg.uservar

TEMPLATE_API_VERSION = "1.0.0"


class Package(zeekpkg.template.Package):
    def contentdir(self):
        return "package"

    def needed_user_vars(self):
        return ["name"]

    def validate(self, tmpl):
        # One cannot currently combine a Spicy analyzer and a general-purpose
        # plugin via features. Users who need this should start from either and
        # generalize as needed.
        have_plugin = False

        analyzers = 0

        for feature in self._features:
            if isinstance(feature, Plugin):
                have_plugin = True
            if isinstance(feature, SpicyProtocolAnalyzer):
                analyzers += 1
            if isinstance(feature, SpicyFileAnalyzer):
                analyzers += 1
            if isinstance(feature, SpicyPacketAnalyzer):
                analyzers += 1

        if have_plugin and analyzers > 0:
            raise zeekpkg.template.InputError(
                'the "plugin" and "spicy-[file|packet|protocol]-analyzer" features are mutually exclusive'
            )

        if analyzers > 1:
            raise zeekpkg.template.InputError(
                "can use only one of the spicy-*-analyzers features at a time"
            )

        if not tmpl.lookup_param("name"):
            raise zeekpkg.template.InputError("package requires a name")

        if not tmpl.lookup_param("name").isprintable():
            raise zeekpkg.template.InputError(
                f'invalid package name "{tmpl.lookup_param("name")}"'
            )

        if tmpl.lookup_param("ns") and not tmpl.lookup_param("ns").isalnum():
            raise zeekpkg.template.InputError(
                f'package namespace "{tmpl.lookup_param("ns")}" must be alphanumeric'
            )


class Plugin(zeekpkg.template.Feature):
    def name(self):
        return "plugin"

    def contentdir(self):
        return os.path.join("features", self.name())

    def needed_user_vars(self):
        return ["namespace"]

    def validate(self, tmpl):
        if not tmpl.lookup_param("ns"):
            raise zeekpkg.template.InputError("plugins require a namespace")

        if not tmpl.lookup_param("ns").isalnum():
            raise zeekpkg.template.InputError(
                f'package namespace "{tmpl.lookup_param("ns")}" must be alphanumeric'
            )


class License(zeekpkg.template.Feature):
    def name(self):
        return "license"

    def contentdir(self):
        return os.path.join("features", self.name())

    def license_keys(self, tmpl):
        licdir = os.path.join(tmpl.templatedir(), self.contentdir())
        return sorted(os.listdir(licdir))

    def needed_user_vars(self):
        return ["author", "license"]

    def validate(self, tmpl):
        if not tmpl.lookup_param("author"):
            raise zeekpkg.template.InputError("license requires an author")
        if not tmpl.lookup_param("license"):
            raise zeekpkg.template.InputError("license requires a license type")
        if tmpl.lookup_param("license") not in self.license_keys(tmpl):
            types_str = ", ".join(self.license_keys(tmpl))
            raise zeekpkg.template.InputError(
                "license type must be one of " + types_str
            )

    def instantiate(self, tmpl):
        # We reimplement this to select a specific input file instead of a
        # folder walk -- we only need a single output for this feature.
        prefix = os.path.join(tmpl.templatedir(), self.contentdir())
        in_file = os.path.join(prefix, tmpl.lookup_param("license"))
        with open(in_file, "rb") as hdl:
            out_content = self._replace(tmpl, hdl.read())
        self.instantiate_file(
            tmpl,
            os.path.join(prefix, tmpl.lookup_param("license")),
            "",
            "COPYING",
            out_content,
        )


class GithubCi(zeekpkg.template.Feature):
    def name(self):
        return "github-ci"

    def contentdir(self):
        return os.path.join("features", self.name())


class SpicyAnalyzer(zeekpkg.template.Feature):
    """Base class for Spicy-based analyzers."""

    def contentdir(self):
        return os.path.join("features", self.name())

    def needed_user_vars(self):
        return ["name", "analyzer"]

    def validate(self, tmpl):
        """Validate feature prerequisites."""
        for parameter in self.needed_user_vars():
            value = tmpl.lookup_param(parameter)
            if not value or len(value) == 0:
                raise zeekpkg.template.InputError(f"package requires a {parameter}")

    def instantiate(self, tmpl):
        # Instead of calling super(), do this ourselves to instantiate symlinks as files.
        for orig_file, path_name, file_name, content in self._walk(tmpl):
            if os.path.islink(orig_file):
                with open(orig_file, "rb") as hdl:
                    content = self._replace(tmpl, hdl.read())

            self.instantiate_file(tmpl, orig_file, path_name, file_name, content)

        # Remove any files marked as unneeded.
        for path in glob.glob(
            os.path.join(self._packagedir, "**/*.REMOVE"), recursive=True
        ):
            os.unlink(path)

        def pkg_file(*name):
            path = os.path.join(self._packagedir, *name)
            assert os.path.exists(path)
            return path

        # Manually merge Spicy analyzer-specific changes to `zkg.meta`.
        with open(pkg_file("zkg.meta"), "ab") as zkg_meta:
            # Add a build command.
            #
            # NOTE: For backwards compatibility with <zkg-2.8.0 which did not
            # inject binary paths of installed packages into `PATH`, we allow
            # as a fallback a `spicyz` path inferred from `zkg`'s directory
            # structure.
            zkg_meta.write(
                b"build_command = mkdir -p build && "
                b"cd build && "
                b"SPICYZ=$(command -v spicyz || echo %(package_base)s/spicy-plugin/build/bin/spicyz) cmake .. && "
                b"cmake --build .\n"
            )

        # Manually merge Spicy analyzer-specific changes to `testing/btest.cfg`.
        with open(pkg_file("testing", "btest.cfg"), "ab") as btest_cfg:
            btest_cfg.write(
                bytes(
                    textwrap.dedent(
                        """\
                DIST=%(testbase)s/..
                # Set compilation-related variables to well-defined state.
                CC=
                CXX=
                CFLAGS=
                CPPFLAGS=
                CXXFLAGS=
                LDFLAGS=
                DYLDFLAGS=
                """
                    ),
                    "ascii",
                )
            )

        # Manually remove files from the primary template that we don't need.
        os.remove(pkg_file("testing", "tests", "run-pcap.zeek"))
        os.remove(pkg_file("testing", "Traces", "http.pcap"))


class SpicyProtocolAnalyzer(SpicyAnalyzer):
    """Feature for a Spicy-based protocol analyzer."""

    def name(self):
        return "spicy-protocol-analyzer"

    def needed_user_vars(self):
        """Specify required user variables."""
        return super().needed_user_vars() + ["protocol", "unit_orig", "unit_resp"]

    def validate(self, tmpl):
        """Validate feature prerequisites."""
        SpicyAnalyzer.validate(self, tmpl)

        protocol = tmpl.lookup_param("protocol_upper")
        if protocol not in ("TCP", "UDP"):
            raise zeekpkg.template.InputError("protocol must be TCP or UDP")


class SpicyFileAnalyzer(SpicyAnalyzer):
    """Feature for a Spicy-based file analyzer."""

    def name(self):
        return "spicy-file-analyzer"

    def needed_user_vars(self):
        """Specify required user variables."""
        return super().needed_user_vars() + ["unit"]


class SpicyPacketAnalyzer(SpicyAnalyzer):
    """Feature for a Spicy-based packet analyzer."""

    def name(self):
        return "spicy-packet-analyzer"

    def needed_user_vars(self):
        """Specify required user variables."""
        return super().needed_user_vars() + ["unit"]


class Template(zeekpkg.template.Template):
    def define_user_vars(self):
        # Try to determine user name and email via the git config. This relies
        # on the fact that zkg itself must have the git module available.
        author = None
        try:
            parser = git.GitConfigParser(config_level="global")
            user_name = parser.get("user", "name", fallback=None)
            user_email = parser.get("user", "email", fallback=None)
            if user_name and user_email:
                author = user_name + " <" + user_email + ">"
        except (NameError, AttributeError):
            pass

        return [
            zeekpkg.uservar.UserVar(
                "name", desc='the name of the package, e.g. "FooBar" or "spicy-http"'
            ),
            zeekpkg.uservar.UserVar(
                "namespace", desc='a namespace for the package, e.g. "MyOrg"'
            ),
            zeekpkg.uservar.UserVar(
                "analyzer",
                desc=(
                    "name of the Spicy analyzer, which typically corresponds to the "
                    'protocol/format being parsed (e.g. "HTTP", "PNG")'
                ),
            ),
            zeekpkg.uservar.UserVar(
                "protocol",
                desc="transport protocol for the analyzer to use: TCP or UDP",
            ),
            zeekpkg.uservar.UserVar(
                "unit",
                desc='name of the top-level Spicy parsing unit for the file/packet format (e.g. "File" or "Packet")',
            ),
            zeekpkg.uservar.UserVar(
                "unit_orig",
                desc=(
                    "name of the top-level Spicy parsing unit for the originator side "
                    'of the connection (e.g. "Request")'
                ),
            ),
            zeekpkg.uservar.UserVar(
                "unit_resp",
                desc=(
                    "name of the top-level Spicy parsing unit for the responder side of "
                    'the connection (e.g. "Reply"); may be the same as originator side'
                ),
            ),
            zeekpkg.uservar.UserVar(
                "author", default=author, desc="your name and email address"
            ),
            zeekpkg.uservar.UserVar(
                "license", desc="one of " + ", ".join(License().license_keys(self))
            ),
        ]

    def apply_user_vars(self, user_vars):
        # pylint: disable=too-many-branches
        for uvar in user_vars:
            if uvar.name() == "name":
                self.define_param("name", uvar.val())
                self.define_param("slug", zeekpkg.uservar.slugify(uvar.val()))

            if uvar.name() == "namespace":
                self.define_param("ns", uvar.val(""))
                self.define_param("ns_colons", uvar.val() + "::" if uvar.val() else "")
                self.define_param(
                    "ns_underscore", uvar.val() + "_" if uvar.val() else ""
                )

            if uvar.name() == "analyzer":
                self.define_param("analyzer", uvar.val())
                self.define_param("analyzer_lower", uvar.val().lower())
                self.define_param("analyzer_upper", uvar.val().upper())

            if uvar.name() == "protocol":
                self.define_param("protocol", uvar.val())
                self.define_param("protocol_lower", uvar.val().lower())
                self.define_param("protocol_upper", uvar.val().upper())

            if uvar.name() == "unit":
                self.define_param("unit", uvar.val())

            if uvar.name() == "unit_orig":
                self.define_param("unit_orig", uvar.val())
                self.define_param(
                    "unit", uvar.val()
                )  # add this for convenience in single-unit templates

            if uvar.name() == "unit_resp":
                self.define_param("unit_resp", uvar.val())

            if uvar.name() == "author":
                self.define_param("author", uvar.val())

            if uvar.name() == "license":
                self.define_param("license", uvar.val())

        self.define_param("year", str(date.today().year))

        # Select alternatives to use for protocol analyzers.
        if self.lookup_param("unit_orig") and self.lookup_param(
            "unit_orig"
        ) == self.lookup_param("unit_resp"):
            self.define_param("ALT-one-unit", "")
            self.define_param("ALT-two-units", ".REMOVE")
        else:
            self.define_param("ALT-one-unit", ".REMOVE")
            self.define_param("ALT-two-units", "")

        if self.lookup_param("protocol_lower") == "tcp":
            self.define_param("ALT-tcp", "")
            self.define_param("ALT-udp", ".REMOVE")
        else:
            self.define_param("ALT-tcp", ".REMOVE")
            self.define_param("ALT-udp", "")

    def package(self):
        return Package()

    def features(self):
        return [
            Plugin(),
            License(),
            GithubCi(),
            SpicyProtocolAnalyzer(),
            SpicyFileAnalyzer(),
            SpicyPacketAnalyzer(),
        ]
