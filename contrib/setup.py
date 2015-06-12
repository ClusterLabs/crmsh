#!/usr/bin/python

from setuptools import setup

setup(name='pygments-crmsh-lexers',
      version='0.0.5',
      description='Pygments crmsh custom lexers.',
      keywords='pygments crmsh lexer',
      license='BSD',

      author='Kristoffer Gronlund',
      author_email='kgronlund@suse.com',

      url='https://github.com/ClusterLabs/crmsh',

      packages=['pygments_crmsh_lexers'],
      install_requires=['pygments>=2.0.2'],

      entry_points='''[pygments.lexers]
                      ANSIColorsLexer=pygments_crmsh_lexers:ANSIColorsLexer
                      CrmshLexer=pygments_crmsh_lexers:CrmshLexer''',

      classifiers=[
          'Environment :: Plugins',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: BSD License',
          'Operating System :: OS Independent',
          'Programming Language :: Python',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 3',
          'Topic :: Software Development :: Libraries :: Python Modules',
      ],)
