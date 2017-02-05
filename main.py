#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import re
from string import letters

import webapp2
import cgi

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

page_header = """
    <!DOCTYPE html>
    <html>
    <head>
    <title>Signup</title>
    <style>
    .error {
    color: red;
    }
    </style>
    </head>
    <body>
    <h1>Signup</h1>
    """

# html boilerplate for the bottom of every page
page_footer = """
    </body>
    </html>
    """

form="""
    <form method="post">
        <table>
            <tr>
            <td><label name="username">Username</label></td>
            <td>
            <input name="username" type="text" value="%(username)s" required>
            <span class="error">%(username_error)s</span>
            </td>
            </tr>

            <tr>
            <td><label name="password">Password</label></td>
            <td>
            <input name="password" type="password"  required>
            <span class="error">%(password_error)s</span>
            </td>
            </tr>

            <tr>
            <td><label for="verify">Verify Password</label></td>
            <td>
            <input name="verify" type="password" required>
            <span class="error">%(verify_error)s</span>
            </td>
            </tr>

            <tr>
            <td><label for="email">Email (optional)</label></td>
            <td>
            <input name="email" type="email" value="%(email)s">
            <span class="error">%(email_error)s</span>
            </td>
            </tr>
        </table>
        <input type="submit">
    </form>"""



content=page_header+form+page_footer

class Signup(webapp2.RequestHandler):
    def write_form(self,username="", email="",username_error="",password_error="",verify_error="",email_error=""):
        self.response.out.write(content % {
                                         "username":username,
                                         "email":email,
                                         "username_error":username_error,
                                         "password_error":password_error,
                                         "verify_error":verify_error,
                                         "email_error":email_error
                                         } )

    def get(self):
        self.write_form()

    def post(self):
        username=self.request.get("username")
        password=self.request.get("password")
        password_confirmation=self.request.get("verify")
        email=self.request.get("email")

        ved_username = valid_username(username)
        ved_password =valid_password(password)
        ved_email = valid_email(email)

        isError=False
        username_error=""
        password_error=""
        email_error=""
        verify_error=""

        if not ved_username:
            username_error="This is not a valid username."
            isError=True

        if not ved_password:
            password_error="This is not a valid password."
            isError=True

        if not ved_email:
            email_error="This is not a valid email."
            isError=True

        if password != password_confirmation:
            verify_error="Passwords don't match."
            isError=True

        if isError:
            self.write_form(username,email,username_error,password_error,verify_error,email_error)
        else:
            self.redirect("/welcome?username="+username)


class Welcome(webapp2.RequestHandler):
    def get(self):
        username=self.request.get("username")

        welcome= "Welcome, "+username+"!"
        welcome_element="<h1>"+welcome+"</h1>"
        self.response.write(welcome_element)




app = webapp2.WSGIApplication([
    ('/', Signup),
    ('/welcome',Welcome)
], debug=True)
