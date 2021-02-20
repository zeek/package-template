import zeekpkg.template
import zeekpkg.uservar

TEMPLATE_API_VERSION = '1.0.0'

class Package(zeekpkg.template.Package):
    def contentdir(self):
        return 'package'

    def needed_user_vars(self):
        return ['name']

    def validate(self, tmpl):
        if not tmpl.lookup_param('name'):
            raise zeekpkg.template.InputError(
                'package requires a name')

        if not tmpl.lookup_param('name').isalnum():
            raise InputError(
                'package name "{}" must be alphanumeric'
                .format(tmpl.lookup_param('name')))

        if tmpl.lookup_param('namespace') and not tmpl.lookup_param('namespace').isalnum():
            raise zeekpkg.template.InputError(
                'package namespace "{}" must be alphanumeric'
                .format(tmpl.lookup_param('namespace')))


class Plugin(zeekpkg.template.Feature):
    def contentdir(self):
        return 'plugin'

    def needed_user_vars(self):
        return ['namespace']

    def validate(self, tmpl):
        if not tmpl.lookup_param('ns'):
            raise zeekpkg.template.InputError(
                'plugins require a namespace')

        if not tmpl.lookup_param('ns').isalnum():
            raise zeekpkg.template.InputError(
                'package namespace "{}" must be alphanumeric'
                .format(tmpl.lookup_param('ns')))


class GithubCi(zeekpkg.template.Feature):
    def contentdir(self):
        return 'github-ci'


class Template(zeekpkg.template.Template):
    def define_user_vars(self):
        return [
            zeekpkg.uservar.UserVar(
                'name', desc='the name of the package, e.g. "FooBar"'),
            zeekpkg.uservar.UserVar(
                'namespace', desc='a namespace for the package, e.g. "MyOrg"'),
        ]

    def apply_user_vars(self, uvars):
        for uvar in uvars:
            if uvar.name() == 'name':
                self.define_param('name', uvar.val())
                self.define_param('slug', zeekpkg.uservar.slugify(uvar.val()))

            if uvar.name() == 'namespace':
                self.define_param('ns', uvar.val(''))
                self.define_param('ns_colons', uvar.val() + '::' if uvar.val() else '')
                self.define_param('ns_underscore', uvar.val() + '_' if uvar.val() else '')

    def package(self):
        return Package()

    def features(self):
        return [Plugin(), GithubCi()]
