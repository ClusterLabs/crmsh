import coverage
import atexit
cov=coverage.Coverage(config_file="/opt/crmsh/test/features/coverage/coveragerc")
atexit.register(lambda:(cov.stop(),cov.save()))
cov.start()
