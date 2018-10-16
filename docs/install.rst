Installation
============

.. note::

   The STIX 2 validator requires Python 2.7 or 3.4+.

The easiest way to install the STIX 2 validator is with pip:

::

  $ pip install stix2-validator

Note that if you instead install it by cloning or downloading the
repository, you will need to set up the submodules before you install
it:

::

  $ git clone https://github.com/oasis-open/cti-stix-validator.git
  $ cd cti-stix-validator/
  $ git submodule update --init --recursive
  $ python setup.py install
