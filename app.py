#
# Copyright 2008 David Noble <dnoble@dnoble.org>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import logging, traceback
import os
import re
import cgi

from google.appengine.api import users
from google.appengine.ext import db
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template
from google.appengine.ext.webapp.util import run_wsgi_app

class RoleAssignment(db.Model):
  user = db.UserProperty(required=True)
  role = db.StringProperty(required=True)

class Page(db.Model):
  url = db.StringProperty(required=True)
  title = db.StringProperty()
  content = db.TextProperty()
  date = db.DateTimeProperty(auto_now_add=True)
  author = db.UserProperty()
  def formatted_date(self):
    return self.date.strftime('%d %b %Y %H:%M:%S')

class PageRenderer(webapp.RequestHandler):
  def get(self, url):
    try:
      page = Page.all().filter('url', url).get()
      if page:
        path = os.path.join(os.path.dirname(__file__), 'html', 'render.html')
        self.response.out.write(template.render(path, { 'page': page, }))
      else:
        self.error(404)
        path = os.path.join(os.path.dirname(__file__), 'html', '404.html')
        self.response.out.write(template.render(path, { }))
    except:
      logging.error(traceback.format_exc())
      self.error(500)
      path = os.path.join(os.path.dirname(__file__), 'html', '500.html')
      self.response.out.write(template.render(path, { }))

class EditRequestHandler(webapp.RequestHandler):
  roles = None

  def respond(self, filename, payload):
    is_dev_env = ('Development' in os.getenv('SERVER_SOFTWARE'))
    env = { 'development': is_dev_env,
            'production': not is_dev_env,
          }
    user = users.get_current_user()
    role = { 'admin': self.has_role(user, 'Admin'),
             'manager': self.has_role(user, 'Manager'),
             'editor': self.has_role(user, 'Editor'),
           }
    role['none'] = self.has_no_roles(user)
    payload['env'] = env
    payload['user'] = user
    payload['role'] = role
    payload['logout_url'] = users.create_logout_url(self.request.uri)
    path = os.path.join(os.path.dirname(__file__), 'html', 'edit', filename)
    logging.info(path)
    self.response.out.write(template.render(path, payload))

  def not_found(self):
    self.error(404)
    path = os.path.join(os.path.dirname(__file__), 'html', 'edit', '404.html')
    self.response.out.write(template.render(path, { }))

  def fail(self):
    logging.error(traceback.format_exc())
    self.error(500)
    path = os.path.join(os.path.dirname(__file__), 'html', 'edit', '500.html')
    self.response.out.write(template.render(path, { }))

  def require_login(self):
    user = users.get_current_user()
    if not user:
      payload = { 'login_url': users.create_login_url(self.request.uri), }
      self.respond('unauthenticated.html', payload)
      return False
    return user

  def get_roles(self, user):
    if self.roles is None:
      self.roles = []
      for a in db.GqlQuery("SELECT * FROM RoleAssignment WHERE user = :1", user):
        self.roles.append(a.role)
      if users.is_current_user_admin():
        self.roles.append('Admin')
    return self.roles

  def has_role(self, user, role):
    return role in self.get_roles(user) or users.is_current_user_admin()

  def has_no_roles(self, user):
    return len(self.get_roles(user)) == 0

  def require_role(self, role):
    user = users.get_current_user()
    if not self.has_role(user, role):
      self.respond('unauthorized.html', { })
      return False
    return True

class RoleAssignmentEditor(EditRequestHandler):
  def get(self, action):
    try:
      if not self.require_login():
        return
      if not self.require_role('Manager'):
        return
      if action == 'list':
        self.show_list()
      elif action == 'add':
        self.show_add_form()
      elif action == 'modify':
        self.show_modify_form()
      elif action == 'delete':
        self.show_delete_form()
      else:
        logging.warn('Unrecognized request action: %s' % action)
        self.not_found()
    except:
      self.fail()

  def post(self, action):
    try:
      if not self.require_login():
        return
      if action == 'add':
        self.apply_add_form()
      elif action == 'modify':
        self.apply_modify_form()
      elif action == 'delete':
        self.apply_delete_form()
      else:
        logging.warn('Unrecognized request action: %s' % action)
        self.not_found()
    except:
      self.fail()

  def show_list(self):
    list = db.GqlQuery("SELECT * FROM RoleAssignment ORDER BY user ASC LIMIT 20")
    for item in list:
      item.id = item.key().id()
    # TODO: paginate
    payload = { 'list': list }
    self.respond('role_assignment_list.html', payload)

  def show_add_form(self):
    self.respond('role_assignment_add.html', { })

  def apply_add_form(self):
    email_address = self.request.get('user')
    user = users.User(email_address)
    role = self.request.get('role')
    # TODO: verify that url is unique & has only valid characters
    role_assignment = RoleAssignment(user=user, role=role)
    key = role_assignment.put()
    self.redirect('/edit/roles/list')

  def show_modify_form(self):
    key = self.request.get('key')
    if not key:
      logging.error('No key for modify form')
      return self.not_found()
    role_assignment = RoleAssignment.get(key)
    if not role_assignment:
      logging.error('RoleAssignment not found for modify form, key=%s', key)
      return self.not_found()
    self.respond('role_assignment_modify.html', { 'role_assignment': role_assignment, })

  def apply_modify_form(self):
    key = self.request.get('key')
    if not key:
      return self.not_found()
    role_assignment = RoleAssignment.get(key)
    if not role_assignment:
      return self.not_found()
    # TODO: verify that user and role are valid
    email_address = self.request.get('user')
    user = users.User(email_address)
    role = self.request.get('role')
    role_assignment.user = user
    role_assignment.role = role
    role_assignment.content = self.request.get('content')
    role_assignment.put()
    self.redirect('/edit/roles/list')

  def show_delete_form(self):
    key = self.request.get('key')
    if not key:
      return self.not_found()
    role_assignment = RoleAssignment.get(key)
    if not role_assignment:
      return self.not_found()
    self.respond('role_assignment_delete.html', { 'role_assignment': role_assignment, })

  def apply_delete_form(self):
    key = self.request.get('key')
    if not key:
      return self.not_found()
    role_assignment = RoleAssignment.get(key)
    if not role_assignment:
      return self.not_found()
    role_assignment.delete()
    self.redirect('/edit/roles/list')

class PageEditor(EditRequestHandler):
  def get(self, action):
    try:
      if not self.require_login():
        return
      if not self.require_role('Editor'):
        return
      if action == 'list':
        self.show_list()
      elif action == 'add':
        self.show_add_form()
      elif action == 'modify':
        self.show_modify_form()
      elif action == 'delete':
        self.show_delete_form()
      else:
        logging.warn('Unrecognized request action: %s' % action)
        self.not_found()
    except:
      self.fail()

  def post(self, action):
    try:
      if not self.require_login():
        return
      if action == 'add':
        self.apply_add_form()
      elif action == 'modify':
        self.apply_modify_form()
      elif action == 'delete':
        self.apply_delete_form()
      else:
        logging.warn('Unrecognized request action: %s' % action)
        self.not_found()
    except:
      self.fail()

  def show_list(self):
    list = db.GqlQuery("SELECT * FROM Page ORDER BY url ASC LIMIT 20")
    for item in list:
      item.id = item.key().id()
    # TODO: paginate
    payload = { 'list': list }
    self.respond('page_list.html', payload)

  def show_add_form(self):
    self.respond('page_add.html', { })

  def apply_add_form(self):
    url = self.request.get('url')
    title = self.request.get('title')
    content = self.request.get('content')
    user = users.get_current_user()
    # TODO: verify that url is unique & has only valid characters
    page = Page(url=url, title=title, content=content, author=user)
    key = page.put()
    self.redirect('/edit/pages/list')

  def show_modify_form(self):
    logging.error('OK')
    key = self.request.get('key')
    if not key:
      logging.error('No key for modify form')
      return self.not_found()
    page = Page.get(key)
    if not page:
      logging.error('Page not found for modify form, key=%s', key)
      return self.not_found()
    self.respond('page_modify.html', { 'page': page, })

  def apply_modify_form(self):
    key = self.request.get('key')
    if not key:
      return self.not_found()
    page = Page.get(key)
    if not page:
      return self.not_found()
    # TODO: verify that url is unique & has only valid characters
    page.url = self.request.get('url')
    page.title = self.request.get('title')
    page.content = self.request.get('content')
    page.put()
    self.redirect('/edit/pages/list')

  def show_delete_form(self):
    key = self.request.get('key')
    if not key:
      return self.not_found()
    page = Page.get(key)
    if not page:
      return self.not_found()
    self.respond('page_delete.html', { 'page': page, })

  def apply_delete_form(self):
    key = self.request.get('key')
    if not key:
      return self.not_found()
    page = Page.get(key)
    if not page:
      return self.not_found()
    page.delete()
    self.redirect('/edit/pages/list')

class EditorConsole(EditRequestHandler):
  def get(self):
    try:
      if not self.require_login():
        return
      user = users.get_current_user()
      if self.has_role(user, 'Editor'):
        self.redirect('/edit/roles/list')
      elif self.has_role(user, 'Manager'):
        self.redirect('/edit/roles/list')
      elif self.has_role(user, 'Admin'):
        self.redirect('/_ah/admin')
      else:
        self.respond('unauthorized.html', { })
    except:
      self.fail()

application = webapp.WSGIApplication([
                ('/edit/roles/(.*)', RoleAssignmentEditor),
                ('/edit/pages/(.*)', PageEditor),
                ('/edit/?', EditorConsole),
                ('(/.*)', PageRenderer),
              ])
def main():
  run_wsgi_app(application)

if __name__ == "__main__":
  main()
