# Releasing a new version

A guide to releasing new versions of crmsh.

## Version scheme

We follow a somewhat loose version of Semantic Versioning, with a
three-part version number:

    <major>.<minor>.<patch>

The major version number is increased rarely, arbitrarily and
indicates big changes to the shell. Moving from Python 2 to Python 3
was such a change, for example. It does not indicate breaking
changes: We try not to make breaking changes at all. If there is a
breaking change, it is hopefully a mistake that would be fixed with a
patch. If not, it should be noted very clearly and probably only
released with a major version number change.

The minor version number indicates new features and bugfixes, but
hopefully no breaking changes.

The patch version number indicates bugfixes only, and no breaking
changes.

## Steps

1. Updating the changelog

In `/ChangeLog`, there is a curated list of changes included in this
release. This log should be updated based on the git history. Remove
any updates that are tagged `dev:` or `test:` since these are internal
changes, and clean up the changelog in any other way you might want.

To get the list of changes since the last release, you can use `git
log` with a custom format. This example gets the changes between 3.0
and 3.0.1, filtering out any changes tagged `dev:` or `test:`:

    PAGER=cat git log --format="- %s" 3.0.0..3.0.1 | \
        grep -Ev -- '-[ ](dev|test):.*'

2. Tagging the release

Using `git tag` you can see the list of existing tags. Depending
on the version being released, you will want to tag the current commit
with that release. Make it a signed tag:

    git tag -s -u <user@example.com> 4.1.0

In the tag message I usually just put

    Release 4.1.0

(of course, change `4.1.0` to whatever release it is you are tagging.

Remember to push the tag to the Github repository. Assuming that the
github repository is `origin`, this command should do the trick:

    git push --tags origin


3. Release email

Send a release email to users@clusterlabs.org. Here is the template
that I usually follow with release emails:

```
Hello everyone!

I'm happy to announce the release of crmsh version <VERSION>.

<DESCRIPTION: some notes about the release>

There are some other changes in this release as well, see the
ChangeLog for the complete list of changes:

* https://github.com/ClusterLabs/crmsh/blob/<VERSION>/ChangeLog

The source code can be downloaded from Github:

* https://github.com/ClusterLabs/crmsh/releases/tag/<VERSION>

Packaged versions of crmsh should be available shortly from your
distribution of choice. Development packages for openSUSE Tumbleweed
are available from the Open Build System, here:

* http://download.opensuse.org/repositories/network:/ha-clustering:/Factory/

Archives of the tagged release:

* https://github.com/ClusterLabs/crmsh/archive/<VERSION>.tar.gz
* https://github.com/ClusterLabs/crmsh/archive/<VERSION>.zip

As usual, a huge thank you to all contributors and users of crmsh!

```

4. Website update

The crmsh website is hosted on Github as a github page. The URL to the
website repository is

    https://github.com/crmsh/crmsh.github.io

The website contents themselves (the sources) are found in the regular
crmsh repository, in the `/doc/website-v1` folder. There is a
`Makefile` in this folder which can be used to regenerate the
website.

Doing this requires `asciidoc` and `Pygments` to be installed, as well
as the custom Pygments filter `ansiclr`.

`ansiclr` is found in the `/contrib/pygments_crmsh_lexers` folder, and
can be installed by running `python setup.py install` in the
`/contrib` folder.

**Note: ansiclr seems to be broken at the moment. Just ignore
it. Everything should still work except some highlighting.**

A container image suitable for building the website can be built using
`toolchain/Containerfile`:

    cd toolchain && podman build -t local/crmsh-doc-builder .

To create the news update, copy a previous update (found in
`/doc/website-v1/news`), rename it to an appropriate name based on the
current date, and replace the contents based on the announcement
email.

Remember to update the title, author and date information at the top
of the news entry, to ensure that it appears correctly on the site.

To add the manpage of new version to the website, run

    podman run --rm -ti -v <crmsh repo root dir>:/opt/crmsh local/crmsh-doc-builder:latest make clean all

Copy `generated-sources/crm.8.aio.adoc` to `website-v1/man-x.x.adoc` and update

   * website-v1/Makefile
   * website-v1/documentation.adoc
   * website-v1/index.adoc

to include the new file and create links to it.

To generate the site including the new entry, run

    podman run --rm -ti -v <crmsh repo root dir>:/opt/crmsh local/crmsh-doc-builder:latest make website

The new site should now sit in `/doc/website-v1/gen`. To update the
site, using rsync should work:

    rsync -av --delete --exclude='.*' doc/website-v1/gen/ <path-to-website-checkout>/crmsh.github.io/

5. Update `network:ha-clustering:Factory`

On the Open Build Service, the project
`network:ha-clustering:Factory/crmsh` is used as the development
project for openSUSE Tumbleweed. This project mirrors the state of the
`master` branch in crmsh, but for policy reasons it is not
automatically updated.

The following steps assumes that you are a maintainer of
`network:ha-clustering:Factory`. If not, you can still make the update
but you will have to branch the `crmsh` package, make the update there
and then submit an update request using `osc submit`. Then a
maintainer will have to review your submission.

To update the package and submit to `openSUSE:Factory`, the following
steps will do the trick. First, check out a local copy of the crmsh
project:

    osc co network:ha-clustering:Factory crmsh
    cd network:ha-clustering:Factory/crmsh

If you already have a copy, make sure it is up to date:

    osc update

Update the `_service` file so that the version number reflects the
latest version of the `master` branch in git.

Pull in the latest changes from git:

    osc service dr

This will update the spec file and the changes file. Clean up the
changes file if you want (not strictly neccessary), and remove any old
tarball still in the package directory, and then add/remove the
changes to osc:

    osc ar

Check that everything looks good, and then commit:

    osc diff
    osc commit

Once the package has built successfully on OBS, you can submit to
`openSUSE:Factory`:

    osc submit

6. Update `network:ha-clustering:Stable`

If this is a minor release for the latest major release, or a new
major release, we should update the version of crmsh hosted at
`network:ha-clustering:Stable` on OBS.

Since `master` is probably up to date with this latest version, doing
so should be as simple as submitting crmsh from
`network:ha-clustering:Factory` to `network:ha-clustering:Stable`.

Once the release is tagged, the announcement email is sent, the
website updated and the packages updated, the release is done.

Congratulations!
