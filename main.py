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
#
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


class Signup(webapp2.RequestHandler):
    def get(self):
        form="""
            <form action="welcome" method="post">
            <table>
                <tr>
                    <td><label for="username">Username</label></td>
                    <td>
                        <input name="username" type="text" value="" required>
                        <span class="error"></span>
                    </td>
                </tr>
                <tr>
                    <td><label for="password">Password</label></td>
                    <td>
                        <input name="password" type="password" required>
                        <span class="error"></span>
                    </td>
                </tr>
                <tr>
                    <td><label for="verify">Verify Password</label></td>
                    <td>
                        <input name="verify" type="password" required>
                        <span class="error"></span>
                    </td>
                </tr>
                <tr>
                    <td><label for="email">Email (optional)</label></td>
                    <td>
                        <input name="email" type="email" value="">
                        <span class="error"></span>
                    </td>
                </tr>
            </table>
            <input type="submit">
            </form>"""

        error = self.request.get("error")
        if error:
            error_element=("<p class='error'>"+
                               cgi.escape(error,quote=True)+
                               "</p>")
        else:
            error_element = ""

        content=page_header+form + error_element + page_footer
        self.response.write(content)



class Welcome(webapp2.RequestHandler):
    def post(self):
        username=self.request.get("username")
        password=self.request.get("password")
        password_confirmation=self.request.get("verify")
        email=self.request.get("email")

        error= None

        if username=="" or password=="" or password_confirmation=="":
            error = "please fill out this field"

        if not valid_username(username):
            error="This is not a valid username!"

        if not valid_password(password):
            error= "This is not a valid password."

        if not valid_email(email):
            error= "This is not a valid email."

        if password != password_confirmation:
            error="Passwords don't match"


        if error != None:
            self.redirect("/?error="+cgi.escape(error, quote=True))

        welcome= "Welcome, "+username+"!"
        welcome_element="<h1>"+welcome+"</h1>"

        self.response.write(welcome_element)


app = webapp2.WSGIApplication([
    ('/', Signup),
    ('/welcome',Welcome)
], debug=True)
