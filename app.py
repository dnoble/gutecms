import logging
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

class BaseRequestHandler(webapp.RequestHandler):
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
    path = os.path.join(os.path.dirname(__file__), 'html', filename)
    self.response.out.write(template.render(path, payload))

  def not_found(self):
    self.error(404)
    path = os.path.join(os.path.dirname(__file__), 'html', '404.html')
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
    if not self.has_role(user, 'Manager'):
      self.respond('unauthorized.html', { })
      return False
    return True

class RoleAssignmentEditor(BaseRequestHandler):
  def get(self, action):
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

  def post(self, action):
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
    self.redirect('/_cms/roles/list')

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
    self.redirect('/_cms/roles/list')

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
    self.redirect('/_cms/roles/list')

class PageEditor(BaseRequestHandler):
  def get(self, action):
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

  def post(self, action):
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
    self.redirect('/_cms/pages/list')

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
    self.redirect('/_cms/pages/list')

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
    self.redirect('/_cms/pages/list')

class EditorConsole(BaseRequestHandler):
  def get(self):
    if not self.require_login():
      return
    self.respond('_cms.html', { })

class PageRenderer(BaseRequestHandler):
  def get(self, url):
    page = Page.all().filter('url', url).get()
    if not page:
      return self.not_found()
    self.respond('render.html', { 'page': page, })

application = webapp.WSGIApplication([
                ('/_cms/roles/(.*)', RoleAssignmentEditor),
                ('/_cms/pages/(.*)', PageEditor),
                ('/_cms/?', EditorConsole),
                ('(/.*)', PageRenderer),
              ])
def main():
  run_wsgi_app(application)

if __name__ == "__main__":
  main()
