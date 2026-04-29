# -*- coding: utf-8 -*-
"""
    MiniTwit Tests
    ~~~~~~~~~~~~~~

    Tests a MiniTwit application.

    :refactored: (c) 2024 by HelgeCPH from Armin Ronacher's original unittest version
    :copyright: (c) 2010 by Armin Ronacher.
    :license: BSD, see LICENSE for more details.
"""
import requests
import uuid


# import schema
# import data
# otherwise use the database that you got previously
BASE_URL = "http://localhost"

def get_unique_username(base_name):
    """Generate a unique username to avoid conflicts in shared databases"""
    return f"{base_name}_{uuid.uuid4().hex[:8]}"

def register(username, password, password2=None, email=None, session=None):
    """Helper function to register a user"""
    if password2 is None:
        password2 = password
    if email is None:
        email = username + '@example.com'

    if session is None:
        http_session = requests.Session()
    else:
        http_session = session

    return (http_session.post(f'{BASE_URL}/register', data={
        'username':     username,
        'password':     password,
        'password2':    password2,
        'email':        email,
    }, allow_redirects=True), http_session)

def login(username, password, session = None):
    """Helper function to login"""
    if session is None:
        http_session = requests.Session()
    else:
        http_session = session
    

    r = http_session.post(f'{BASE_URL}/login', data={
        'username': username,
        'password': password
    }, allow_redirects=True)
    return r, http_session

def register_and_login(username, password):
    """Registers and logs in in one go"""
    http_session = requests.Session()
    r, ses = register(username, password, session=http_session)
    return login(username, password, session=http_session)

def logout(http_session):
    """Helper function to logout"""
    return http_session.get(f'{BASE_URL}/logout', allow_redirects=True)

def add_message(http_session, text):
    """Records a message"""
    r = http_session.post(f'{BASE_URL}/add_message', data={'text': text},
                                allow_redirects=True)
    if text:
        assert 'Your message was recorded' in r.text
    return r

# testing functions

def test_register():
    """Make sure registering works"""
    unique_user = get_unique_username('testuser')
    r, _ = register(unique_user, 'default')
    assert 'You were successfully registered and can login now' in r.text
    r, _ = register(unique_user, 'default')
    assert 'The username is already taken' in r.text
    r, _    = register('', 'default')
    assert 'You have to enter a username' in r.text
    r, _ = register('meh', '')
    assert 'You have to enter a password' in r.text
    r, _ = register('meh', 'x', 'y')
    assert 'The two passwords do not match' in r.text
    r, _ = register('meh', 'foo', email='broken')
    assert 'You have to enter a valid email address' in r.text

def test_login_logout():
    """Make sure logging in and logging out works"""
    unique_user = get_unique_username('loginuser')
    r, http_session = register_and_login(unique_user, 'default')
    
    assert 'You were logged in' in r.text
    r = logout(http_session)
    assert 'You were logged out' in r.text
    r, _ = login(unique_user, 'wrongpassword')
    assert 'Invalid password' in r.text
    r, _ = login('nonexistent_user', 'wrongpassword')
    assert 'Invalid username' in r.text

def test_message_recording():
    """Check if adding messages works"""
    unique_user = get_unique_username('msguser')
    _, http_session = register_and_login(unique_user, 'default')
    add_message(http_session, 'test message 1')
    add_message(http_session, '<test message 2>')
    r = requests.get(f'{BASE_URL}/')
    assert 'test message 1' in r.text
    assert '&lt;test message 2&gt;' in r.text

def test_timelines():
    """Make sure that timelines work"""
    foo_user = get_unique_username('foo')
    bar_user = get_unique_username('bar')
    
    _, http_session = register_and_login(foo_user, 'default')
    add_message(http_session, 'the message by foo')
    logout(http_session)
    _, http_session = register_and_login(bar_user, 'default')
    add_message(http_session, 'the message by bar')
    r = http_session.get(f'{BASE_URL}/public')
    assert 'the message by foo' in r.text
    assert 'the message by bar' in r.text

    # bar's timeline should just show bar's message
    r = http_session.get(f'{BASE_URL}/')
    assert 'the message by foo' not in r.text
    assert 'the message by bar' in r.text

    # now let's follow foo
    r = http_session.get(f'{BASE_URL}/{foo_user}/follow', allow_redirects=True)
    assert 'You are now following &#34;' in r.text and foo_user in r.text

    # we should now see foo's message
    r = http_session.get(f'{BASE_URL}/')
    assert 'the message by foo' in r.text
    assert 'the message by bar' in r.text

    # but on the user's page we only want the user's message
    r = http_session.get(f'{BASE_URL}/{bar_user}')
    assert 'the message by foo' not in r.text
    assert 'the message by bar' in r.text
    r = http_session.get(f'{BASE_URL}/{foo_user}')
    assert 'the message by foo' in r.text
    assert 'the message by bar' not in r.text

    # now unfollow and check if that worked
    r = http_session.get(f'{BASE_URL}/{foo_user}/unfollow', allow_redirects=True)
    assert 'You are no longer following &#34;' in r.text and foo_user in r.text
    r = http_session.get(f'{BASE_URL}/')
    assert 'the message by foo' not in r.text
    assert 'the message by bar' in r.text

