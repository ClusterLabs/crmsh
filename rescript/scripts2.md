# Cluster Scripts

Goal: The next revision of cluster scripts should serve both as a
funcionally complete and easy-to-use replacement for the crmsh
templates, and as a more capable and complete replacement for the hawk
wizards.

Key features:

- Easy to write: It should be easy to implement all of the scenarios
  covered by the existing wizards and templates.

- Capable: Should be able to have optional steps, multiple-step
  application and configuring resources completely including
  installation of packages and basic configuration files.

- Require no coding: The most common scenarios should be expressable
  purely through steps in the .yml file and a simple mustache-like
  templating in string values.

## Structure

A cluster script is a folder containing at least a `main.yml` file,
containing the high-level description of the script. It may optionally
include other files, for example configuration files, or python
scripts similarly to the crmsh 2.0 cluster scripts.


## XML version

Instead of a `main.yml` document, it should be possible to write a
`main.xml` document which has exactly the same structure but uses a
syntax more like the Hawk wizard syntax.

## JSON API

There should be a JSON API that hawk can use.

1. list: input: id. return list of available cluster scripts with id, short
and long description plus category
2. info: input: id. return detailed information about a cluster script, which
parameters it may take and everything needed to know about the
parameters, everything needed to apply the changes. Parameters have
category which may be nested, so you can have a parameter which is in
the category Database/Filesystem, where an included database resource
in turn includes a filesystem resource. This should be displayed as a
hierarchy visually.
3. dryrun: input: id, parameter values. Returns details about what
steps will be taken and the CIB changes to apply
4. apply: input: id, parameter values. Returns progress line-by-line,
so hawk can display the progress interactively with a progress bar.
In case of error, returns an error description. Which step failed, on
which nodes (if applicable).

## interactive terminal interface

One idea is to have a curses-based terminal interface to a cluster
script, for the interactive mode. That may be overkill at first.

## commmand-line style

A cluster script should be invokable via the command line like the
current cluster scripts. The commands should be the same as for the
json API.

## agents.yml

Along with the cluster scripts, there should be some general cluster
script configuration data. The thing I have in mind for now is
agents.yml, which is a document that augments the agent metadata where
such is lacking. For example, adding parameter validation info,
overriding default timeouts, better descriptions, category for the
agent as well as classifying parameters as basic or advanced.

The eventual goal would be to migrate as much of this as possible into
the OCF metadata, but for non-OCF agents this kind of data is
necessary even so.


## optional sections

There are option parameters, which turn on or off parts of the cluster
script. Including other agents or scripts can be optional, in which
case the name of the include (include "as" name) becomes an option
value that can be used to include/exclude steps or to have conditional
sections of the cib.

There should also be a way to express "Either select an existing
resource or configure a resource of this type". This could be handled
by having a parameter with the same name as an included resource. The
parameter can be told to respond to a particular key via the key
field. So {{thing}} would expand to an empty string, but {{thing:id}}
would expand to the id of the existing resource. Hmm. Actually, you'd
want any attribute.. actually, we should refer to an existing resource
and get the parameter values from it. But we still want {{thing}} to
expand to the empty string... hrm. A little bit strange, but makes
some kind of sense in this context.

## requiring sudo

THIS IS WRONG:
Steps can require sudo access, in which case the script needs to ask
for root password. The root password should then be passed as a
special parameter when applying. When applying on the command line,
crmsh would ask for the root password so that it doesn't have to be
typed on the command line.

Here's how it really works: To access other nodes, we need remote
passwordless access. This is set up by ha-cluster-bootstrap for the
root user. So whenever we access other nodes, we do so as the root
user anyway. Therefore all remote access requires the root
password. This is dealt with in hawk, completely, and needs no further
support from the cluster scripts system. Thus all the stuff about
passing sudo through is unnecessary, and the cluster scripts
themselves don't have to worry about it: We just assume that we're
running as root or a user that is privileged to do the things we want
to do.

## validation

agents.yml adds parameter validation information, by adding a richer
set of content types and also allowing regular expressions as
validation strings (enclosed in slashes).

TODO: Before applying the script, check the parameter values by
calling <agent> validate-all?

## Backwards compatibility

For the crmsh templates and the hawk wizards, support is feature
complete for sure. There's nothing missing there. However for the
current crmsh cluster scripts, they are way more complex and more
capable than this variant can ever be. The ideal would be to be able
to support all of the scripts actions (apply_local, collect, validate)
etc. in the scripts 2.0 scripts too, so that scripts 2.0 can run the
old scripts without modification. If I can do that... it would be
fantastic, then I can get rid of the original scripts code at least.

I should reimplement the crmsh templates as cluster scripts but still
support them so that anyone who has written their own templates can
still use them. I should also translate hawk wizards to cluster
scripts on the fly, so that if you pass a hawk workflow .xml as the
cluster script to run, it actually generates the in-memory data for a
cluster script 2.0 and runs that. It shouldn't be too hard actually.

That way, everything old still works, and the new stuff still works,
and cluster scripts are just as capable as they've always been but now
a lot easier to use for most cases.


## JSON API

What would the JSON API look like? We'd want to get real-time feed to
the progress, so that should be output line by line...

1. list: ==>
[{name, shortdesc, longdesc, category} ...]
OR
[{error}]

2. describe: <name> ==>
{name, shortdesc, longdesc, category, parameters}
OR
{error}

3. verify: <name> <parameters> ==>
[{shortdesc, longdesc, nodes}]
OR
{error}

4. apply: <name> <parameters> ==>
[{shortdesc, longdesc, nodes, status [, error]}]

Apply should be interactive!


## Differences

Instead of allowing partial application and running step-by-step,
always perform all steps but make steps optional based on
parameters. So you can have a step that is only performed if a certain
option is set, and that is controlled entirely by the
parameters. There is no partial application, and there is no
configuration management-style facting step: Package installation is
done using zypper or similar on all nodes, if the packages are already
installed that's great.

There shouldn't be any need for sudo or root password: hawk can always
run crm as root using the Invoker, and we count on having passwordless
ssh access to all nodes.

Actually it's a massive security hole since the hacluster user can do
anything via crm cluster run. But then, the hacluster user controls
the cluster anyway, so...

## conversion

I should write the new scripts engine as it should be without any
compatibility consideration. Then add a preprocessing step which
converts an old-style wizard to a new-style cluster script. The
old-style cluster scripts are called as-is, they are still useful.
The old-style crmsh templates are converted to new-style cluster
scripts manually, and removed from crmsh. This also allows us to make
"template" mean a single thing in crmsh.



## commands

crm script list
crm script describe <name>
crm script verify <name> <params>...
crm script apply <name> <params>...

crm script convert <template>|<wizard>|<script 1.0>
crm script api <command> <params>...


## moving from scripts 1.0 to 2.0

There are really a few main things missing from the scripts 1.0 to make
them usable:

1. Support for configuring a CIB in a easier way than writing a python
script and invoking it.

2. Support for including another script as a sub-step / partial.

3. Support for having optional steps via on/off parameters.

4. Support for executing commands or small bash snippets directly.

5. Categories for parameters and scripts.

so,

1. a new top-level section: include:

2. New step actions:

  - call
  - install - ensure that the given packages are installed
  - service - ensure that the given service states are enforced
  - cib - apply the given CIB
  

## from hawk wizards

the hawk override construction means "use this as the default value
for this parameter instead of whatever the default was". Maybe a more
intuitive approach is to merge the contents of parameters in the
include template block with the parameters in the actual template to
get the final information.


Parameters should have the same elements as resource agent parameters
as far as possible:

- name
- unique (?) Means that other instances of this agent cannot be
  configured with the same value. For example, a virtual IP.
- required (?) Should default to true, I think.
- longdesc
- shortdesc
- default
- type - basic types plus /<regex>/, [choice1, choice2, ...], file,
  device, directory, port, ipaddress, <n>..<m>

Yeah. Should switch from "name+description" to
"name+shortdesc+longdesc" for both scripts and parameters.


# stepwise execution

There's no reason not to keep supporting this! In fact, we should be
able to be mostly backwards-compatible with earlier scripts.

# XML document format

There's no reason this shouldn't be doable either! Just need a

XML -> Script() parser.


# simplified agent inheritance

When an agent is included, you could of course insert it in a CIB and
a reasonable default primitive will be created for it.

The required parameters of that agent will be exposed as parameters
for the script, unless there are explicit parameters in the script
that override those parameters. For example, if there is a "ip"
parameter that has "from: IPaddr2", then the ip parameter of IPaddr2
will not be directly exposed, but the default description and value,
etc. for the ip parameter will be taken from the IPaddr2 metadata.
