Welcome to PySess's documentation!
==================================

PySess is a Python library to provide cookie-based session support to Python
WSGI applications. It aims to provide an alternative for the well-known
`Beaker`_ session system. It was written with a clean user interface in mind
and takes many inspirations from the above mentioned `Beaker`_, `django`_ and
also some minor ideas from `RoR`_. If you are further interested in the history
and reason behind PySess, check out `Motivation`_.

Contrary to both django and Beaker, PySess uses ``json`` instead of ``pickle``
by default to store data. This is done mostly for security reasons, a more
in-depth explanation can also be found in `Motivation`_.


.. todo::
    Ref for Motivation

.. _Beaker: http://beaker.readthedocs.org/
.. _django: https://www.djangoproject.com/
.. _RoR: http://rubyonrails.org/

Generally, there are two kinds of users of this libary:

1. Those who seek to use it directly through a standard WSGI application
2. Those who use a readily available wrapper for their framework and are mostly
   interested in configuration.

For both kinds the `Configuration`_ section is probably the most interesting.
For users of kind 1) there is also a neat example of how to integrate the
session into their WSGI application. Beyond that, you might find the
documentation for the basic public session API useful

.. todo::
    Refs for configuration, example and public API.

.. toctree::
   :maxdepth: 2

   usage
   api





Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

