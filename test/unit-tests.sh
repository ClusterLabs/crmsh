#!/bin/sh
case `pwd` in
	*/test/unittests)
		PYTHONPATH=../.. nosetests . "$@"
		;;
	*/test)
		PYTHONPATH=.. nosetests unittests "$@"
		;;
	*)
		PYTHONPATH=. nosetests test/unittests "$@"
		;;
esac

