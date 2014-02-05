#!/bin/sh
case `pwd` in
	*/test/unittests)
		PYTHONPATH=../../modules nosetests -w . "$@"
		;;
	*/test)
		PYTHONPATH=../modules nosetests -w unittests "$@"
		;;
	*)
		PYTHONPATH=modules nosetests -w test/unittests "$@"
		;;
esac

