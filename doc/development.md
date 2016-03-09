# Notes for developers and contributors

This is mostly a list of notes that Dejan prepared for me when I
started working on crmsh (me being Kristoffer). I've decided to update
it at least enough to not be completely outdated, so the information
here should be mostly up-to-date for crmsh 2.1.

## data-manifest

This file contains a list of all shared data files to install.

Whenever a file that is to be installed to `/usr/share/crmsh` is added,
for example a cluster script or crmsh template, the `data-manifest`
file needs to be regenerated, by running `./update-data-manifest.sh`.

## Website

To build the website, you will need **Asciidoc**, **Pygments** plus
two special lexers for Pygments installed as a separate module. This
module is included in the source tree for crmsh under `contrib`. To
install the module and build the website, do the following:

```
cd contrib
sudo python setup.py install
cd ..
cd doc/website-v1
make
```

If everything worked out as it should, the website should now be
generated in `doc/website-v1/gen`.

## Modules

This is the list of all modules including short descriptions.

- `crm`

	The program. Tries to detect incompatible python versions or a
    missing crmsh module, and report an understandable error message
    in either case.

- `crmsh/main.py`

    This is where execution really starts. Verifies the environment
	and detects the pacemaker version.

- `crmsh/config.py`

    Reads the `crm.conf` configuration file and tries to detect basic
    information about where pacemaker is located etc. Some magic is
    used to generate an object hierarchy based on the configuration,
    so that the rest of the code can access configuration variables
    directly.

- `crmsh/constants.py`

    Various hard-coded constants. Many of these should probably be
    read from pacemaker metadata for better compatibility across
    different versions.
 
- `crmsh/ui_*.py`

    The UI context (`ui_context.py`) parses the input command and
    keeps track of which is the current level in the UI. `ui_root.py`
    is the root of the UI hierarchy.

- `crmsh/help.py`

	Reads help from a text file and presents parts of it in
	response to the help command. The text file has special
	anchors to demarcate help topics and command help text.

- `doc/crm.8.adoc`

	Online help in asciidoc format. Several help topics (search
	for +[[topic_+) and command reference (search for
	+[[cmdhelp_+). Every user interface change needs to be
	reflected here. _Actually, every user interface change has to
	start here_. A source for the +crm(8)+ man page too.

- `crmsh/cibconfig.py`

	Configuration (CIB) manager. Implements the configure level.
	The bigest and the most complex part. There are three major
	classes:

	- +CibFactory+: operations on the CIB or parts of it.

	- +CibObject+: every CIB element is implemented in a
	subclass of +CibObject+. The configuration consists of a
	set of +CibObject+ instances (subclassed, e.g. +CibNode+ or
	+CibPrimitive+).

	- +CibObjectSet+: enables operations on sets of CIB
	elements. Two subclasses with CLI and XML presentations
	of cib elements. Most operations are going via these
	subclasses (+show+, +edit+, +save+, +filter+).

- `crmsh/scripts.py`

    Implements the cluster scripts. Reads multiple kinds of script
    definition languages including the XML wizard format used by
    Hawk.

- `crmsh/handles.py`

    A primitive handlebar-style templating language used in cluster
    scripts.

- `crmsh/idmgmt.py`

	CIB id management. Guarantees that all ids are unique.
	A helper for CibFactory.

- `crmsh/parse.py`

    Parses CLI -> XML.

- `crmsh/cliformat.py`

    Parses XML -> CLI.

    Not as cleanly separated as the CLI parser, mostly a set of
    functions called from `cibconfig.py`.

- `crmsh/clidisplay.py`, `crmsh/term.py`

	Applies colors to terminal output.

- `crmsh/crm_gv.py`

	Interface to GraphViz. Generates graph specs for dotty(1).

- `crmsh/cibstatus.py`

	CIB status section editor and manipulator (cibstatus
	level). Interface to crm_simulate.

- `crmsh/ra.py`

	Resource agents interface.

- `crmsh/rsctest.py`

	Resource tester (configure rsctest command).

- `crmsh/history.py`

	Cluster history. Interface to logs and other artifacts left
	on disk by the cluster.

- `crmsh/log_patterns.py`, `log_patterns_118.py`

	Pacemaker subsystems' log patterns. For versions earlier than
	1.1.8 and the latter.

- `crmsh/schema.py`, `pacemaker.py`

	Support for pacemaker RNG schema.

- `crmsh/cache.py`

    A very rudimentary cache implementation. Used to cache
	results of expensive operations (i.e. ra meta).

- `crmsh/crm_pssh.py`

    Interface to the parallax library for remote SSH commands.

- `crmsh/corosync.py`

    Parse and edit the `corosync.conf` configuration file.

- `crmsh/msg.py`

	Messages for users. Can count lines and include line
	numbers. Needs refinement.

- `crmsh/utils.py`

	A bag of useful functions. Needs more order.

- `crmsh/xmlutil.py`

	A bag of useful XML functions. Needs more order.

## Code improvements

These are some thoughts on how to improve maintainability and
make crmsh nicer. Mostly for people looking at the code, the
users shouldn't notice much (or any) difference.

Everybody's invited to comment and make further suggestions, in
particular experienced pythonistas.

### Syntax highlighting

- syntax highlighting is done before producing output, which
  is basically wrong and makes code convoluted; it further
  makes extra processing more difficult

- use a python library (pygments seems to be the best
  candidate); that should also allow other output formats
  (not only terminal)

- how to extend pygments to understand a new language? it'd
  be good to be able to get this _without_ pushing the parser
  upstream (that would take _long_ to propagate to
  distributions)

### CibFactory is huge

- this is a single central CIB class, it'd be good to have it
  split into several smaller classes (how?)

### The element create/update procedure is complex

- not sure how to improve this

### Bad namespace separation

- xmlutil and utils are just a loose collection of functions,
  need to be organized better (get rid of 'from xyz import *')
