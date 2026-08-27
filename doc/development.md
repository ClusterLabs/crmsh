## Code improvements / TODO

These are some thoughts on how to improve maintainability and
make crmsh nicer. Mostly for people looking at the code, the
users shouldn't notice much (or any) difference.

Everybody's invited to comment and make further suggestions, in
particular experienced pythonistas.

### Validate more using pacemaker schema

- We have the pacemaker CIB schema available (see schema.py),
however using it is difficult and so it is not used in enough
places.

### Investigate switching to python-prompt-toolkit

Either switch crmsh over to using the prompt toolkit for
implementing the interactive mode, or at least look at it
to see what ideas we can lift.

https://github.com/jonathanslenders/python-prompt-toolkit

### Better version detection

Be better at detecting and handling the Pacemaker version.
Ensure backwards compatibility, for example with old vs.
new ACL command syntax.

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
