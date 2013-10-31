===========
Usage Guide
===========

Quickstart
==========

PySess features a pre-configurable session factory called `pysess.sessionmaker`
which allows you to create new sessions easily by just calling the configured
``sessionmaker`` with required session data. Here is an example setup using a
basic `dogpile.cache` backend:

.. code-block:: python
    
    from pysess import sessionmaker
    from dogpile.cache import make_region
    Session = sessionmaker()
    region = make_region().configure('dogpile.cache.memory')
    Session.configure(backend='dogpile', domain='example.com', region=region)

This uses the ``dogpile.cache`` backend with a memory cache on the domain
``example.com``. Note how we provided our own region: For full flexibility, you
directly provide a region instead of arguments getting passed along.
Additionally, this allows you to use the same region for caching and sessions.

Now let us work with the session:

.. code-block:: python

    session = Session()
    session["some_key"] = "some value"
    cookie = session.save()

    # reload session
    previous_session = Session(str(cookie))
    print previous_session["some_key"]
    # prints "some value"

Let's take a look at each line individually. First, we create a new session
instance. Right now, not much has happened - it is not saved anywhere and there
is no data in it. In the second line, we store a value in the session. Note how
we can use the session as a dictionary. In the third step, we want to persist
the session to the backend. We call the ``save`` method and get a cookie which
can be handed out to the client. Note that what you receive here is not a
string, it is a cookie class. This allows for more fine-grained control before
you pass it out to a client. In our little example this does not do much.

Now let's assume we gave this cookie out to a client and got it back. In the
next step, we want to reload the old session. We do this by calling our session
factory again - but this time we pass in a cookie (here we need it to be a
string, not a class, so we explicitly cast it. We have now successfully
reloaded the session. Let's retrieve the value from it. In this new session, we
find our old session by the use of the session ID stored in the cookie. It will
print our previously stored value.


Configuration
=============

Now that you have seen how to use it, you will probably want to adjust the
configuration to your needs. Configuration consists of three basic parts:

- sessionmaker-only configuration
- General backend configuration
- backend-specific configuration

Because of this separation, all three parts are documented separately on their
classes. However, you can always pass all three parts in one common dictionary
to the sessionmaker and it will split them apart itself.

For the sessionmaker-only configuration, see
:meth:`pysess.sessionmaker.configure`. For the general backend configuration,
see :meth:`pysess.session.backends.BaseSession`. And finally, for the
backend-specific part, see the relevant backend documentation, e.g.
:meth:`pysess.session.backends.DogpileSession` for dogpile.cache backend
configuration.
