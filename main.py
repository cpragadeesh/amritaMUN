#!/usr/bin/env python

import webapp2
import os
import jinja2
import re
import hashlib
import urllib2
import time
import random
import string
from collections import namedtuple
from google.appengine.ext import db

template_dir_mun = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env_mun = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir_mun))

sessions = {}  #(key = gl(session id):value = Delagate object)

class Delegate(db.Model):
    name = db.StringProperty(required = True)
    insti = db.StringProperty(required = True)
    email = db.StringProperty(required = True)
    phone = db.StringProperty(required = True)
    accm = db.StringProperty(required = True)
    country = db.StringProperty()
    admin = db.StringProperty()
    passwrd = db.StringProperty()

    def generate_password_hash(self, passwrd):
        return hashlib.sha256(passwrd).hexdigest()

class handler_mun(webapp2.RequestHandler):
    def write(self, *a, **kwarg):
        self.response.write(*a, **kwarg)

    def render_str(self, template, **params):
        t = jinja_env_mun.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class AmritaMun(handler_mun):
    def get(self):
        self.render("home.html")

class MunRegister(handler_mun):
    def get(self):
        self.render("register_mun.html")

    def post(self):
        name = self.request.get('name')
        insti = self.request.get("insti")
        email = self.request.get('email')
        phone = self.request.get('phone')
        accm = self.request.get('accm')
        admin = '0'   # '1' if admin else '0', access given only through console.developers.google.com

        new_profile = Delegate(name = name, insti = insti, email = email, phone = phone, accm = accm, admin = admin)
        new_profile.passwrd = new_profile.generate_password_hash(self.request.get('passwrd'))
        new_profile.put()

        self.redirect('/confirmed')

class Thankyou(handler_mun):
    def get(self):
        self.render("ty.html")

class Login(handler_mun):

    def verify(self, username, password):
        d = db.GqlQuery("SELECT * FROM Delegate WHERE email=:1", username)
        d = d.get()
        if d:
            print d.email + " " + username
            if d.email == username:
                print password + " " + hashlib.sha256(password).hexdigest() + " " + d.passwrd
                if hashlib.sha256(password).hexdigest() == d.passwrd:
                    return d
                else:
                    return False

        else:
            return False

    def get(self):
        self.render('login.html', error='')

    def post(self):
        email = self.request.get('email')
        password = self.request.get('passwrd')
        valid = self.verify(email, password)
        if (valid):
            gl = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(15))
            sessions[gl] = valid
            self.response.headers.add_header('Set-Cookie', 'gl=%s'%gl)
            if valid.admin == '1':
                self.redirect('/hq')
            else:
                self.redirect('/delegate')
        else:
            self.render("login.html", error="Incorrect username or password.")

class DelegatePage(handler_mun):
    def get(self):
        gl = self.request.cookies.get('gl')
        if(gl in sessions):
            self.render('/delegate.html', d=sessions[gl])
        else:
            self.redirect('/login')

    def post(self):
        gl = self.request.cookies.get('gl')
        sessions[gl] = ""
        gl = ""
        self.response.headers.add_header('Set-Cookie', 'gl=%s'%gl)
        self.render("/signout.html")

class HQ(handler_mun):

    def get(self):
        gl = self.request.cookies.get('gl')
        if(gl in sessions):
            delegates = db.GqlQuery("SELECT * FROM Delegate")
            self.render('/hq.html', delegates=delegates)

    def post(self):
        delegates = db.GqlQuery("SELECT * FROM Delegate")
        for d in delegates:
            c = self.request.get(d.email)
            print c
            if(c != d.country and c != "none"):
                d.country = c
                d.put()

        self.redirect('/hq')

app = webapp2.WSGIApplication([
    ('/', AmritaMun),
    ('/register', MunRegister),
    ('/confirmed', Thankyou),
    ('/hq', HQ),
    ('/login', Login),
    ('/delegate', DelegatePage)
], debug=True)
