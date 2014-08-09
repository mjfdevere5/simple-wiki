import webapp2
from google.appengine.ext import ndb
from google.appengine.api import memcache
import logging

import jinja2
import cgi

import re
import time
import os

import hmac
import hashlib
import random
import string


template_dir = os.path.join(os.path.dirname(__file__),"templates")
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
								autoescape=True)


### Global variables and functions
SECRET = 'Y6MPHpKiO0Pd5QR3rKOrhuPcDZLN2Dq3PXiw41hgZaapzz5u1w'

def make_secure_val(val):
	return val + "|" + hmac.new(SECRET, val).hexdigest()

def get_val_if_secure(secure_val):
	val = secure_val.split("|")[0]
	if secure_val == make_secure_val(val):
		return val

def make_random(length):
	return ''.join(random.choice(string.letters \
					+ string.digits) for _ in range(length))

def make_salt():
	return make_random(10)

def make_pw_hash(name, pw, salt=None):
	if not salt:
		salt = make_salt()
	hashed_pw = hashlib.sha256(name + pw + salt).hexdigest()
	return salt + ',' + hashed_pw

def valid_pw(name, pw, hashed_pw):
	salt = hashed_pw.split(',')[0]
	return hashed_pw == make_pw_hash(name, pw, salt)

default_content = """<h3>This is the default page content</h3> 
<p>This page has probably never been edited before.</p>"""

default_author = "max_de_vere"

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
	return not email or EMAIL_RE.match(email)

def escape_html(s):
	return cgi.escape(s, quote = True)


### Memcache stuff
def get_mem_entity(path, update=False):
	mem_entity = memcache.get("content_%s" % path)
	if update or not mem_entity:
		content_entity = PageContent.get_latest_ten_by_path(path).get()
		if not content_entity:
			content_entity = PageContent(parent=page_key(),
										path=path,
										content=default_content,
										user=default_author,
										ever_edited=False)
		memcache.set("content_%s" % path, content_entity)
		mem_entity = content_entity
	return mem_entity


def get_mem_history(path, update=False):
	mem_history = memcache.get("history_%s" % path)
	if update or not mem_history:
		history = PageContent.get_latest_ten_by_path(path)
		if history:
			history = list(history)
		memcache.set("history_%s" % path, history)
		mem_history = history
	return mem_history


def get_mem_page_by_id(keyid, update=False):
	mem_page = memcache.get("keyid_%s" % str(keyid))
	if update or not mem_page:
		page = PageContent.get_page_by_id(keyid)
		logging.debug("page: %s" % repr(page))
		if page:
			memcache.set("keyid_%s" % str(keyid), page)
		mem_page = page
	return mem_page


### Database models
def page_key(name='default'):
	return ndb.Key('page_type', name)

class PageContent(ndb.Model):
	"""Holds the latest state of any given wikipage"""
	path = ndb.StringProperty(required=True)
	content = ndb.TextProperty(required=True)
	user = ndb.StringProperty(required=True)
	# should this be a User key?
	created = ndb.DateTimeProperty(auto_now_add=True)
	last_updated = ndb.DateTimeProperty(auto_now=True)
	ever_edited = ndb.BooleanProperty()

	@classmethod
	def get_latest_ten_by_path(cls, path):
		logging.debug("NDB query")
		return cls.gql("WHERE ANCESTOR IS :1 "
						"AND path = :2 "
						"ORDER BY last_updated DESC "
						"LIMIT 100",
						page_key(), path)

	@classmethod
	def get_page_by_id(cls, keyid):
		logging.debug("NDB query")
		return cls.get_by_id(int(keyid), parent=page_key())


def user_key(name='default'):
	return ndb.Key('user_key', name)

class User(ndb.Model):
	username = ndb.StringProperty(required=True)
	hashed_pw = ndb.StringProperty(required=True)
	member_since = ndb.DateTimeProperty(auto_now_add=True)
	email = ndb.StringProperty()

	@classmethod
	def get_user_by_username(cls, username):
		return cls.gql("WHERE username = :1 "
						"AND ANCESTOR IS :2 ",
						username, user_key()).get()

	@classmethod
	def register(cls, username, password, email):
		hashed_pw = make_pw_hash(username, password)
		new_user = cls(parent=user_key(), username=username,
						hashed_pw=hashed_pw, email=email)
		return new_user

	@classmethod
	def get_user_by_id(cls, user_id):
		return cls.get_by_id(user_id, parent=user_key())



### Base Handler
class WikiHandler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.write(*a, **kw)

	def render_str(self, template, **params):
		if self.user:
			params['user'] = self.user.username
		t = jinja_env.get_template(template)
		return t.render(**params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.set_cookie(name, cookie_val)

	def get_val_from_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and get_val_if_secure(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key.id()))

	def logout(self):
		self.response.delete_cookie('user_id')

	@staticmethod
	def check_direction(next_url):
		if not next_url or next_url.startswith('/login') \
					or next_url.startswith('/signup') \
					or next_url.startswith('/logout') \
					or next_url.startswith('/logoutandregister'):
			next_url = '/'
		return next_url

	def get_next_url(self):
		return self.request.headers.get('referer','/')

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.get_val_from_cookie('user_id')
		self.user = uid and User.get_user_by_id(int(uid))


### Page Handlers
class View(WikiHandler):
	def get(self, path):
		keyid = self.request.get('v') # implement this
		if keyid:
			entity = get_mem_page_by_id(keyid)
			if not entity:
				return
		else:
			entity = get_mem_entity(path)
		editable_content = entity.content
		if entity.ever_edited or not self.user:
			self.render("wikipage.html",
					editable_content=editable_content,
					path=path)
		else:
			self.redirect('/_edit' + path)


class Edit(WikiHandler):
	def get(self, path):
		if not self.user:
			self.redirect("/login")
		else:
			old_content = get_mem_entity(path).content
			self.render("edit.html", old_content=old_content,
										path=path)

	def post(self, path):
		if not self.user:
			self.write("you're not logged in!")
		else:
			new_content = self.request.get("content")
			page_content = PageContent(parent=page_key(),
										path=path,
										content=new_content,
										user=self.user.username,
										ever_edited=True)
			page_content.put()
			get_mem_entity(path, True)
			get_mem_history(path, True)
			self.redirect(path)


class History(WikiHandler):
	def get(self, path):
		if not self.user:
			self.redirect("/login")
		else:
			history = get_mem_history(path)
			if not history:
				self.write("""No page history to display.
								<br>Return to 
								<a href='%s'>page</a>?""" % path)
			else:
				table = History.create_table(history, path)
				self.render("history.html", path=path,
											table=table)

	@staticmethod
	def create_table(history, path):
		html_str = """<tr><th>#</th><th>Updated</th><th>Begins...</th>
						<th>Author</th><th>View</th></tr>"""
		for i in range(len(history)):
			counter = str(i+1)
			date = history[i].last_updated.strftime('%d %b %Y %X')
			content = escape_html(history[i].content[:100])
			user = history[i].user
			path = path
			keyid = str(history[i].key.id())
			row = History.create_row(counter, date, content, user, path, keyid)
			html_str += row
		return html_str
	
	@staticmethod
	def create_row(counter, date, content, user, path, keyid):
		return """<tr><td>%s</td><td>%s</td><td>%s</td>
					<td>%s</td><td>%s</td></tr>""" % \
					(counter, date, content, user,
						"<a href='%s?v=%s'>view</a>" % \
							(path,keyid))



### User registration and login
class Signup(WikiHandler):
	def get(self):
		next_url = self.get_next_url()
		if self.user:
			self.write("You are already logged in as <b>" + \
						self.user.username + \
						"""</b>.
							<br>
							Would you like to
							<a href='/logoutandregister'>
								logout and register as a new user
							</a>?
							<br>
							Back to <a href='/'>homepage</a>?""")
		else:
			self.render("register.html", next_url=next_url)

	def post(self):
		next_url = str(self.request.get('next_url'))
		next_url = WikiHandler.check_direction(next_url)
		logging.debug("next_url: %s" % next_url)

		self.username = self.request.get("username")
		self.password = self.request.get("password")
		self.verify = self.request.get("verify")
		self.email = self.request.get("email")

		params = dict(username = self.username, email = self.email)

		have_error = False
		if not valid_username(self.username):
			params['error_username'] = "that's not a valid username"
			have_error = True
		if not valid_password(self.password):
			params['error_password'] = "that's not a valid password"
			have_error = True
		elif self.verify != self.password:
			params['error_verify'] = "your passwords don't match"
			have_error = True
		if not valid_email(self.email):
			params['error_email'] = "that's not a valid email"
			have_error = True

		if not have_error:
			user = User.get_user_by_username(self.username)
			if user or self.username == default_author:
				params['error_username'] = "that username is taken"
				have_error = True

		if have_error:
			self.render("register.html", **params)
		else:
			new_user = User.register(self.username, self.password, self.email)
			new_user.put()
			self.login(new_user)
			self.redirect(next_url)


class Login(WikiHandler):
	def get(self):
		next_url = self.get_next_url()

		if self.user:
			self.write("you're already logged in as <b>" + \
						self.user.username + "</b>")
		else:
			self.render("login.html", next_url=next_url)

	def post(self):
		next_url = str(self.request.get('next_url'))
		next_url = WikiHandler.check_direction(next_url)

		self.username = self.request.get('username')
		self.password = self.request.get('password')

		user = User.get_user_by_username(self.username)
		if not user:
			self.render("login.html", username=self.username,
						error_login="that username is not registered")
		else:
			if valid_pw(self.username, self.password, user.hashed_pw):
				self.login(user)
				self.redirect(next_url)
			else:
				self.render("login.html", username=self.username,
							error_login="invalid password")


class Logout(WikiHandler):
	def get(self):
		next_url = str(self.request.get('next_url'))
		next_url = WikiHandler.check_direction(next_url)
		self.logout()
		self.redirect(next_url)


class LogoutAndRegister(WikiHandler):
	def get(self):
		self.logout()
		self.redirect("/signup")


### URI routing
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([("/_edit" + PAGE_RE, Edit),
								("/_history" + PAGE_RE, History),
								("/signup/?", Signup),
								("/login/?", Login),
								("/logout/?", Logout),
								("/logoutandregister/?", LogoutAndRegister),
								(PAGE_RE, View)],
								debug = True)



