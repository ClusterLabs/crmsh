#!/usr/bin/env python
import crm_script
import init_common as init
try:
    crm_script.exit_ok(init.info())
except Exception, e:
    crm_script.exit_fail(str(e))
