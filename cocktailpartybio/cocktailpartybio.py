#!/usr/bin/env python

import logging
import os.path
import itertools
from Question import Test
from Question import Question

import webapp2
from webapp2_extras import auth
from webapp2_extras import sessions
from webapp2_extras.auth import InvalidAuthIdError
from webapp2_extras.auth import InvalidPasswordError

from google.appengine.ext.webapp import template

def user_required(handler):
  """
    Decorator that checks if there's a user associated with the current session.
    Will also fail if there's no session present.
  """
  def check_login(self, *args, **kwargs):
    auth = self.auth
    if not auth.get_user_by_session():
      self.redirect(self.uri_for('login'), abort=True)
    else:
      return handler(self, *args, **kwargs)

  return check_login

class BaseHandler(webapp2.RequestHandler):
  @webapp2.cached_property
  def auth(self):
    """Shortcut to access the auth instance as a property."""
    return auth.get_auth()

  @webapp2.cached_property
  def user_info(self):
    """Shortcut to access a subset of the user attributes that are stored
    in the session.

    The list of attributes to store in the session is specified in
      config['webapp2_extras.auth']['user_attributes'].
    :returns
      A dictionary with most user information
    """
    return self.auth.get_user_by_session()

  @webapp2.cached_property
  def user(self):
    """Shortcut to access the current logged in user.

    Unlike user_info, it fetches information from the persistence layer and
    returns an instance of the underlying model.

    :returns
      The instance of the user model associated to the logged in user.
    """
    u = self.user_info
    return self.user_model.get_by_id(u['user_id']) if u else None

  @webapp2.cached_property
  def user_model(self):
    """Returns the implementation of the user model.

    It is consistent with config['webapp2_extras.auth']['user_model'], if set.
    """
    return self.auth.store.user_model

  @webapp2.cached_property
  def session(self):
      """Shortcut to access the current session."""
      return self.session_store.get_session(backend="datastore")

  def render_template(self, view_filename, params=None):
    if not params:
      params = {}
    user = self.user_info
    params['user'] = user
    path = os.path.join(os.path.dirname(__file__), 'views', view_filename)
    self.response.out.write(template.render(path, params))

  def display_message(self, message):
    """Utility function to display a template with a simple message."""
    params = {
      'message': message
    }
    self.render_template('message.html', params)

  # this is needed for webapp2 sessions to work
  def dispatch(self):
      # Get a session store for this request.
      self.session_store = sessions.get_store(request=self.request)

      try:
          # Dispatch the request.
          webapp2.RequestHandler.dispatch(self)
      finally:
          # Save all sessions.
          self.session_store.save_sessions(self.response)

class MainHandler(BaseHandler):
    def get(self):

        self.render_template('home.html')

class AboutHandler(BaseHandler):
    def get(self):

        self.render_template('about.html')

class SignupHandler(BaseHandler):
  def get(self):
    self.render_template('signup.html')

  def post(self):
    user_name = self.request.get('username')
    email = self.request.get('email')
    name = self.request.get('name')
    password = self.request.get('password')
    last_name = self.request.get('lastname')
    level = 0

    unique_properties = ['email_address']
    user_data = self.user_model.create_user(user_name,
      unique_properties,level = level,
      email_address=email, name=name, password_raw=password,
      last_name=last_name, verified=False)
    if not user_data[0]: #user_data is a tuple
      self.display_message('Username already in use. Pick another, please!')
      return

    user = user_data[1]
    user_id = user.get_id()

    token = self.user_model.create_signup_token(user_id)

    verification_url = self.uri_for('verification', type='v', user_id=user_id,
      signup_token=token, _full=True)

    msg = 'Click <a href="{url}">HERE</a> to verify your account.'

    self.display_message(msg.format(url=verification_url))

class ForgotPasswordHandler(BaseHandler):
  def get(self):
    self._serve_page()

  def post(self):
    username = self.request.get('username')

    user = self.user_model.get_by_auth_id(username)
    if not user:
      logging.info('Could not find any user entry for username %s', username)
      self._serve_page(not_found=True)
      return

    user_id = user.get_id()
    token = self.user_model.create_signup_token(user_id)

    verification_url = self.uri_for('verification', type='p', user_id=user_id,
      signup_token=token, _full=True)

    msg = 'Click <a href="{url}">HERE</a> to reset password.'

    self.display_message(msg.format(url=verification_url))
  
  def _serve_page(self, not_found=False):
    username = self.request.get('username')
    params = {
      'username': username,
      'not_found': not_found
    }
    self.render_template('forgot.html', params)

class VerificationHandler(BaseHandler):
  def get(self, *args, **kwargs):
    user = None
    user_id = kwargs['user_id']
    signup_token = kwargs['signup_token']
    verification_type = kwargs['type']

    user, ts = self.user_model.get_by_auth_token(int(user_id), signup_token,
      'signup')

    if not user:
      logging.info('Could not find any user with id "%s" signup token "%s"',
        user_id, signup_token)
      self.abort(404)

    self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)
    #self.user.level = 1

    if verification_type == 'v':
      self.user_model.delete_signup_token(user.get_id(), signup_token)

      if not user.verified:
        user.verified = True
        user.put()
      self.render_template('authenticated.html')
      return

    elif verification_type == 'p':

      params = {
        'user': user,
        'token': signup_token
      }
      self.render_template('resetpassword.html', params)
    else:
      logging.info('verification type not supported')
      self.abort(404)

class SetPasswordHandler(BaseHandler):

  @user_required
  def post(self):
    password = self.request.get('password')
    old_token = self.request.get('t')

    if not password or password != self.request.get('confirm_password'):
      self.display_message('passwords do not match')
      return

    user = self.user
    user.set_password(password)
    user.put()

    # remove signup token, we don't want users to come back with an old link
    self.user_model.delete_signup_token(user.get_id(), old_token)
    
    self.display_message('Password updated')

class LoginHandler(BaseHandler):
  def get(self):
    self._serve_page()

  def post(self):
    username = self.request.get('username')
    password = self.request.get('password')
    try:
      u = self.auth.get_user_by_password(username, password, remember=True, save_session=True)

      self.redirect(self.uri_for('home'))
    except (InvalidAuthIdError, InvalidPasswordError) as e:
      logging.info('Login failed for user %s because of %s', username, type(e))
      self._serve_page(True)

  def _serve_page(self, failed=False):
    username = self.request.get('username')
    params = {
      'username': username,
      'failed': failed
    }
    self.render_template('login.html', params)

class LogoutHandler(BaseHandler):
  def get(self):
    self.auth.unset_session()
    self.redirect(self.uri_for('home'))

class AuthenticatedHandler(BaseHandler):
    @user_required
    def get(self):

        self.render_template('authenticated.html')

class LevelHandler(BaseHandler):
    @user_required
    def get(self):
        user = self.user
        test = user.level
        test2 = self.auth.get_session_data()

        params = {
            'test': test,
            'test2': test2
        }
        self.render_template('level.html', params)
    def post(self):

        #self.user.raise_level()
        self.user.set_level(3)
        currdata = self.auth.get_session_data(pop=True)
        self.auth.set_session(self.auth.store.user_to_dict(self.user), remember=True)

        self.user.put()
        self.redirect(self.uri_for('level'))


class DashHandler(BaseHandler):
    @user_required
    def get(self):
        text = ""
        if self.user.get_level() == 0:
            text = "Hey, " + self.user.name + ". You haven't completed any modules. Why don't you start with Level 0?"
        elif self.user.get_level() == 1:
            text = "You have completed Level " + str(self.user.get_level()-1) + ". You are at least 5% more charming now."
        elif self.user.get_level() == 2:
            text = "You have completed Level " + str(self.user.get_level()-1) + ". Maybe your ex-girlfriend will want you back."
        elif self.user.get_level() == 3:
            text = "You have completed Level " + str(self.user.get_level()-1) + ". You can definitely win an argument against Donald Trump."
        elif self.user.get_level() == 4:
            text = "You have completed Level " + str(self.user.get_level()-1) + ". Feeling the burn yet?"
        elif self.user.get_level() == 5:
            text = "You have completed Level " + str(self.user.get_level()-1) + ". One more push and then you're all done. Sounds familiar."
        elif self.user.get_level() > 5:
            text = "You have completed Cocktail Party Biology! Break out the whiskey, and lets talk science."
        params = {
            'text': text
        }
        self.render_template('dash.html', params)

class TutorialHandler0(BaseHandler):
    @user_required
    def get(self):
        if self.user.level >= 0:
            t_level = 0
            params = {
                't_level' : t_level
            }
            self.render_template('tutorial.html', params)
        else:
            self.display_message('Hey there, ' + self.user.name + '. Your zeal is impressive, but you need to complete Level 0 before attempting Level 1.')

class QuizHandler0(BaseHandler):
    @user_required
    def get(self):
        level = 0
        if self.user.level == level:
            q_level = level
            params = {
                'q_level' : q_level
            }
            self.render_template('quiz.html', params)
        elif self.user.level < level:
            self.display_message('Hey there, ' + self.user.name + '. Your zeal is impressive, but you need to complete Level ' + str(level - 1) +' before attempting Level ' + str(level) + '.')
        else:
            self.display_message('Come on, ' + self.user.name + '. You already did this one. Find a new schtick. Perhaps Level ' + str(self.user.level) + '?')

    def post(self):

        q_level = 0
        if not (self.user.level == q_level):
            self.render_template('youredrunk.html')
            return
        test_obj = Test(q_level)
        test_qs = test_obj.get_questions()
        test_answers = test_obj.answer_string()

        question1 = test_qs[0].get_questiontext()
        a_1_A = test_qs[0].get_answerstext(1)
        a_1_B = test_qs[0].get_answerstext(2)
        a_1_C = test_qs[0].get_answerstext(3)
        a_1_D = test_qs[0].get_answerstext(4)

        question2 = test_qs[1].get_questiontext()
        a_2_A = test_qs[1].get_answerstext(1)
        a_2_B = test_qs[1].get_answerstext(2)
        a_2_C = test_qs[1].get_answerstext(3)
        a_2_D = test_qs[1].get_answerstext(4)

        question3 = test_qs[2].get_questiontext()
        a_3_A = test_qs[2].get_answerstext(1)
        a_3_B = test_qs[2].get_answerstext(2)
        a_3_C = test_qs[2].get_answerstext(3)
        a_3_D = test_qs[2].get_answerstext(4)

        question4 = test_qs[3].get_questiontext()
        a_4_A = test_qs[3].get_answerstext(1)
        a_4_B = test_qs[3].get_answerstext(2)
        a_4_C = test_qs[3].get_answerstext(3)
        a_4_D = test_qs[3].get_answerstext(4)

        question5 = test_qs[4].get_questiontext()
        a_5_A = test_qs[4].get_answerstext(1)
        a_5_B = test_qs[4].get_answerstext(2)
        a_5_C = test_qs[4].get_answerstext(3)
        a_5_D = test_qs[4].get_answerstext(4)

        params = {
            'q_level': q_level,
            'test_answers': test_answers,
            'question1': question1,
            'a_1_A' : a_1_A,
            'a_1_B' : a_1_B,
            'a_1_C' : a_1_C,
            'a_1_D' : a_1_D,
            'question2': question2,
            'a_2_A' : a_2_A,
            'a_2_B' : a_2_B,
            'a_2_C' : a_2_C,
            'a_2_D' : a_2_D,
            'question3': question3,
            'a_3_A' : a_3_A,
            'a_3_B' : a_3_B,
            'a_3_C' : a_3_C,
            'a_3_D' : a_3_D,
            'question4': question4,
            'a_4_A' : a_4_A,
            'a_4_B' : a_4_B,
            'a_4_C' : a_4_C,
            'a_4_D' : a_4_D,
            'question5': question5,
            'a_5_A' : a_5_A,
            'a_5_B' : a_5_B,
            'a_5_C' : a_5_C,
            'a_5_D' : a_5_D,
        }

        self.render_template('quizpage.html', params)

class TutorialHandler1(BaseHandler):
    @user_required

    def get(self):
        level = 1
        if self.user.level >= level:
            t_level = level
            params = {
                't_level' : t_level
            }
            self.render_template('tutorial.html', params)
        else:
            self.display_message('Hey there, ' + self.user.name + '. Your zeal is impressive, but you need to complete Level ' + str(level - 1) +' before attempting Level ' + str(level) + '.')

class QuizHandler1(BaseHandler):
    @user_required
    def get(self):
        level = 1
        if self.user.level == level:
            q_level = level
            params = {
                'q_level' : q_level
            }
            self.render_template('quiz.html', params)
        elif self.user.level < level:
            self.display_message('Hey there, ' + self.user.name + '. Your zeal is impressive, but you need to complete Level ' + str(level - 1) +' before attempting Level ' + str(level) + '.')
        else:
            self.display_message('Come on, ' + self.user.name + '. You already did this one. Find a new schtick. Perhaps Level ' + str(self.user.level) + '?')
    def post(self):
        q_level = 1
        if not (self.user.level == q_level):
            self.render_template('youredrunk.html')
            return
        test_obj = Test(q_level)
        test_qs = test_obj.get_questions()
        test_answers = test_obj.answer_string()

        question1 = test_qs[0].get_questiontext()
        a_1_A = test_qs[0].get_answerstext(1)
        a_1_B = test_qs[0].get_answerstext(2)
        a_1_C = test_qs[0].get_answerstext(3)
        a_1_D = test_qs[0].get_answerstext(4)

        question2 = test_qs[1].get_questiontext()
        a_2_A = test_qs[1].get_answerstext(1)
        a_2_B = test_qs[1].get_answerstext(2)
        a_2_C = test_qs[1].get_answerstext(3)
        a_2_D = test_qs[1].get_answerstext(4)

        question3 = test_qs[2].get_questiontext()
        a_3_A = test_qs[2].get_answerstext(1)
        a_3_B = test_qs[2].get_answerstext(2)
        a_3_C = test_qs[2].get_answerstext(3)
        a_3_D = test_qs[2].get_answerstext(4)

        question4 = test_qs[3].get_questiontext()
        a_4_A = test_qs[3].get_answerstext(1)
        a_4_B = test_qs[3].get_answerstext(2)
        a_4_C = test_qs[3].get_answerstext(3)
        a_4_D = test_qs[3].get_answerstext(4)

        question5 = test_qs[4].get_questiontext()
        a_5_A = test_qs[4].get_answerstext(1)
        a_5_B = test_qs[4].get_answerstext(2)
        a_5_C = test_qs[4].get_answerstext(3)
        a_5_D = test_qs[4].get_answerstext(4)

        params = {
            'q_level': q_level,
            'test_answers': test_answers,
            'question1': question1,
            'a_1_A' : a_1_A,
            'a_1_B' : a_1_B,
            'a_1_C' : a_1_C,
            'a_1_D' : a_1_D,
            'question2': question2,
            'a_2_A' : a_2_A,
            'a_2_B' : a_2_B,
            'a_2_C' : a_2_C,
            'a_2_D' : a_2_D,
            'question3': question3,
            'a_3_A' : a_3_A,
            'a_3_B' : a_3_B,
            'a_3_C' : a_3_C,
            'a_3_D' : a_3_D,
            'question4': question4,
            'a_4_A' : a_4_A,
            'a_4_B' : a_4_B,
            'a_4_C' : a_4_C,
            'a_4_D' : a_4_D,
            'question5': question5,
            'a_5_A' : a_5_A,
            'a_5_B' : a_5_B,
            'a_5_C' : a_5_C,
            'a_5_D' : a_5_D,
        }

        self.render_template('quizpage.html', params)

class TutorialHandler2(BaseHandler):
    @user_required

    def get(self):
        level = 2
        if self.user.level >= level:
            t_level = level
            params = {
                't_level' : t_level
            }
            self.render_template('tutorial.html', params)
        else:
            self.display_message('Hey there, ' + self.user.name + '. Your zeal is impressive, but you need to complete Level ' + str(level - 1) +' before attempting Level ' + str(level) + '.')

class QuizHandler2(BaseHandler):
    @user_required
    def get(self):
        level = 2
        if self.user.level == level:
            q_level = level
            params = {
                'q_level' : q_level
            }
            self.render_template('quiz.html', params)
        elif self.user.level < level:
            self.display_message('Hey there, ' + self.user.name + '. Your zeal is impressive, but you need to complete Level ' + str(level - 1) +' before attempting Level ' + str(level) + '.')
        else:
            self.display_message('Come on, ' + self.user.name + '. You already did this one. Find a new schtick. Perhaps Level ' + str(self.user.level) + '?')
    def post(self):
        q_level = 2
        if not (self.user.level == q_level):
            self.render_template('youredrunk.html')
            return
        test_obj = Test(q_level)
        test_qs = test_obj.get_questions()
        test_answers = test_obj.answer_string()

        question1 = test_qs[0].get_questiontext()
        a_1_A = test_qs[0].get_answerstext(1)
        a_1_B = test_qs[0].get_answerstext(2)
        a_1_C = test_qs[0].get_answerstext(3)
        a_1_D = test_qs[0].get_answerstext(4)

        question2 = test_qs[1].get_questiontext()
        a_2_A = test_qs[1].get_answerstext(1)
        a_2_B = test_qs[1].get_answerstext(2)
        a_2_C = test_qs[1].get_answerstext(3)
        a_2_D = test_qs[1].get_answerstext(4)

        question3 = test_qs[2].get_questiontext()
        a_3_A = test_qs[2].get_answerstext(1)
        a_3_B = test_qs[2].get_answerstext(2)
        a_3_C = test_qs[2].get_answerstext(3)
        a_3_D = test_qs[2].get_answerstext(4)

        question4 = test_qs[3].get_questiontext()
        a_4_A = test_qs[3].get_answerstext(1)
        a_4_B = test_qs[3].get_answerstext(2)
        a_4_C = test_qs[3].get_answerstext(3)
        a_4_D = test_qs[3].get_answerstext(4)

        question5 = test_qs[4].get_questiontext()
        a_5_A = test_qs[4].get_answerstext(1)
        a_5_B = test_qs[4].get_answerstext(2)
        a_5_C = test_qs[4].get_answerstext(3)
        a_5_D = test_qs[4].get_answerstext(4)

        params = {
            'q_level': q_level,
            'test_answers': test_answers,
            'question1': question1,
            'a_1_A' : a_1_A,
            'a_1_B' : a_1_B,
            'a_1_C' : a_1_C,
            'a_1_D' : a_1_D,
            'question2': question2,
            'a_2_A' : a_2_A,
            'a_2_B' : a_2_B,
            'a_2_C' : a_2_C,
            'a_2_D' : a_2_D,
            'question3': question3,
            'a_3_A' : a_3_A,
            'a_3_B' : a_3_B,
            'a_3_C' : a_3_C,
            'a_3_D' : a_3_D,
            'question4': question4,
            'a_4_A' : a_4_A,
            'a_4_B' : a_4_B,
            'a_4_C' : a_4_C,
            'a_4_D' : a_4_D,
            'question5': question5,
            'a_5_A' : a_5_A,
            'a_5_B' : a_5_B,
            'a_5_C' : a_5_C,
            'a_5_D' : a_5_D,
        }

        self.render_template('quizpage.html', params)

class TutorialHandler3(BaseHandler):
    @user_required

    def get(self):
        level = 3
        if self.user.level >= level:
            t_level = level
            params = {
                't_level' : t_level
            }
            self.render_template('tutorial.html', params)
        else:
            self.display_message('Hey there, ' + self.user.name + '. Your zeal is impressive, but you need to complete Level ' + str(level - 1) +' before attempting Level ' + str(level) + '.')

class QuizHandler3(BaseHandler):
    @user_required
    def get(self):
        level = 3
        if self.user.level == level:
            q_level = level
            params = {
                'q_level' : q_level
            }
            self.render_template('quiz.html', params)
        elif self.user.level < level:
            self.display_message('Hey there, ' + self.user.name + '. Your zeal is impressive, but you need to complete Level ' + str(level - 1) +' before attempting Level ' + str(level) + '.')
        else:
            self.display_message('Come on, ' + self.user.name + '. You already did this one. Find a new schtick. Perhaps Level ' + str(self.user.level) + '?')
    def post(self):
        q_level = 3
        if not (self.user.level == q_level):
            self.render_template('youredrunk.html')
            return
        test_obj = Test(q_level)
        test_qs = test_obj.get_questions()
        test_answers = test_obj.answer_string()

        question1 = test_qs[0].get_questiontext()
        a_1_A = test_qs[0].get_answerstext(1)
        a_1_B = test_qs[0].get_answerstext(2)
        a_1_C = test_qs[0].get_answerstext(3)
        a_1_D = test_qs[0].get_answerstext(4)

        question2 = test_qs[1].get_questiontext()
        a_2_A = test_qs[1].get_answerstext(1)
        a_2_B = test_qs[1].get_answerstext(2)
        a_2_C = test_qs[1].get_answerstext(3)
        a_2_D = test_qs[1].get_answerstext(4)

        question3 = test_qs[2].get_questiontext()
        a_3_A = test_qs[2].get_answerstext(1)
        a_3_B = test_qs[2].get_answerstext(2)
        a_3_C = test_qs[2].get_answerstext(3)
        a_3_D = test_qs[2].get_answerstext(4)

        question4 = test_qs[3].get_questiontext()
        a_4_A = test_qs[3].get_answerstext(1)
        a_4_B = test_qs[3].get_answerstext(2)
        a_4_C = test_qs[3].get_answerstext(3)
        a_4_D = test_qs[3].get_answerstext(4)

        question5 = test_qs[4].get_questiontext()
        a_5_A = test_qs[4].get_answerstext(1)
        a_5_B = test_qs[4].get_answerstext(2)
        a_5_C = test_qs[4].get_answerstext(3)
        a_5_D = test_qs[4].get_answerstext(4)

        params = {
            'q_level': q_level,
            'test_answers': test_answers,
            'question1': question1,
            'a_1_A' : a_1_A,
            'a_1_B' : a_1_B,
            'a_1_C' : a_1_C,
            'a_1_D' : a_1_D,
            'question2': question2,
            'a_2_A' : a_2_A,
            'a_2_B' : a_2_B,
            'a_2_C' : a_2_C,
            'a_2_D' : a_2_D,
            'question3': question3,
            'a_3_A' : a_3_A,
            'a_3_B' : a_3_B,
            'a_3_C' : a_3_C,
            'a_3_D' : a_3_D,
            'question4': question4,
            'a_4_A' : a_4_A,
            'a_4_B' : a_4_B,
            'a_4_C' : a_4_C,
            'a_4_D' : a_4_D,
            'question5': question5,
            'a_5_A' : a_5_A,
            'a_5_B' : a_5_B,
            'a_5_C' : a_5_C,
            'a_5_D' : a_5_D,
        }

        self.render_template('quizpage.html', params)

class TutorialHandler4(BaseHandler):
    @user_required

    def get(self):
        level = 4
        if self.user.level >= level:
            t_level = level
            params = {
                't_level' : t_level
            }
            self.render_template('tutorial.html', params)
        else:
            self.display_message('Hey there, ' + self.user.name + '. Your zeal is impressive, but you need to complete Level ' + str(level - 1) +' before attempting Level ' + str(level) + '.')

class QuizHandler4(BaseHandler):
    @user_required
    def get(self):
        level = 4
        if self.user.level == level:
            q_level = level
            params = {
                'q_level' : q_level
            }
            self.render_template('quiz.html', params)
        elif self.user.level < level:
            self.display_message('Hey there, ' + self.user.name + '. Your zeal is impressive, but you need to complete Level ' + str(level - 1) +' before attempting Level ' + str(level) + '.')
        else:
            self.display_message('Come on, ' + self.user.name + '. You already did this one. Find a new schtick. Perhaps Level ' + str(self.user.level) + '?')
    def post(self):
        q_level = 4
        if not (self.user.level == q_level):
            self.render_template('youredrunk.html')
            return
        test_obj = Test(q_level)
        test_qs = test_obj.get_questions()
        test_answers = test_obj.answer_string()

        question1 = test_qs[0].get_questiontext()
        a_1_A = test_qs[0].get_answerstext(1)
        a_1_B = test_qs[0].get_answerstext(2)
        a_1_C = test_qs[0].get_answerstext(3)
        a_1_D = test_qs[0].get_answerstext(4)

        question2 = test_qs[1].get_questiontext()
        a_2_A = test_qs[1].get_answerstext(1)
        a_2_B = test_qs[1].get_answerstext(2)
        a_2_C = test_qs[1].get_answerstext(3)
        a_2_D = test_qs[1].get_answerstext(4)

        question3 = test_qs[2].get_questiontext()
        a_3_A = test_qs[2].get_answerstext(1)
        a_3_B = test_qs[2].get_answerstext(2)
        a_3_C = test_qs[2].get_answerstext(3)
        a_3_D = test_qs[2].get_answerstext(4)

        question4 = test_qs[3].get_questiontext()
        a_4_A = test_qs[3].get_answerstext(1)
        a_4_B = test_qs[3].get_answerstext(2)
        a_4_C = test_qs[3].get_answerstext(3)
        a_4_D = test_qs[3].get_answerstext(4)

        question5 = test_qs[4].get_questiontext()
        a_5_A = test_qs[4].get_answerstext(1)
        a_5_B = test_qs[4].get_answerstext(2)
        a_5_C = test_qs[4].get_answerstext(3)
        a_5_D = test_qs[4].get_answerstext(4)

        params = {
            'q_level': q_level,
            'test_answers': test_answers,
            'question1': question1,
            'a_1_A' : a_1_A,
            'a_1_B' : a_1_B,
            'a_1_C' : a_1_C,
            'a_1_D' : a_1_D,
            'question2': question2,
            'a_2_A' : a_2_A,
            'a_2_B' : a_2_B,
            'a_2_C' : a_2_C,
            'a_2_D' : a_2_D,
            'question3': question3,
            'a_3_A' : a_3_A,
            'a_3_B' : a_3_B,
            'a_3_C' : a_3_C,
            'a_3_D' : a_3_D,
            'question4': question4,
            'a_4_A' : a_4_A,
            'a_4_B' : a_4_B,
            'a_4_C' : a_4_C,
            'a_4_D' : a_4_D,
            'question5': question5,
            'a_5_A' : a_5_A,
            'a_5_B' : a_5_B,
            'a_5_C' : a_5_C,
            'a_5_D' : a_5_D,
        }

        self.render_template('quizpage.html', params)

class TutorialHandler5(BaseHandler):
    @user_required

    def get(self):
        level = 5
        if self.user.level >= level:
            t_level = level
            params = {
                't_level' : t_level
            }
            self.render_template('tutorial.html', params)
        else:
            self.display_message('Hey there, ' + self.user.name + '. Your zeal is impressive, but you need to complete Level ' + str(level - 1) +' before attempting Level ' + str(level) + '.')

class QuizHandler5(BaseHandler):
    @user_required
    def get(self):
        level = 5
        if self.user.level == level:
            q_level = level
            params = {
                'q_level' : q_level
            }
            self.render_template('quiz.html', params)
        elif self.user.level < level:
            self.display_message('Hey there, ' + self.user.name + '. Your zeal is impressive, but you need to complete Level ' + str(level - 1) +' before attempting Level ' + str(level) + '.')
        else:
            self.display_message('Come on, ' + self.user.name + '. You already did this one. Find a new schtick. Perhaps Level ' + str(self.user.level) + '?')
    def post(self):
        q_level = 5
        if not (self.user.level == q_level):
            self.render_template('youredrunk.html')
            return
        test_obj = Test(q_level)
        test_qs = test_obj.get_questions()
        test_answers = test_obj.answer_string()

        question1 = test_qs[0].get_questiontext()
        a_1_A = test_qs[0].get_answerstext(1)
        a_1_B = test_qs[0].get_answerstext(2)
        a_1_C = test_qs[0].get_answerstext(3)
        a_1_D = test_qs[0].get_answerstext(4)

        question2 = test_qs[1].get_questiontext()
        a_2_A = test_qs[1].get_answerstext(1)
        a_2_B = test_qs[1].get_answerstext(2)
        a_2_C = test_qs[1].get_answerstext(3)
        a_2_D = test_qs[1].get_answerstext(4)

        question3 = test_qs[2].get_questiontext()
        a_3_A = test_qs[2].get_answerstext(1)
        a_3_B = test_qs[2].get_answerstext(2)
        a_3_C = test_qs[2].get_answerstext(3)
        a_3_D = test_qs[2].get_answerstext(4)

        question4 = test_qs[3].get_questiontext()
        a_4_A = test_qs[3].get_answerstext(1)
        a_4_B = test_qs[3].get_answerstext(2)
        a_4_C = test_qs[3].get_answerstext(3)
        a_4_D = test_qs[3].get_answerstext(4)

        question5 = test_qs[4].get_questiontext()
        a_5_A = test_qs[4].get_answerstext(1)
        a_5_B = test_qs[4].get_answerstext(2)
        a_5_C = test_qs[4].get_answerstext(3)
        a_5_D = test_qs[4].get_answerstext(4)

        params = {
            'q_level': q_level,
            'test_answers': test_answers,
            'question1': question1,
            'a_1_A' : a_1_A,
            'a_1_B' : a_1_B,
            'a_1_C' : a_1_C,
            'a_1_D' : a_1_D,
            'question2': question2,
            'a_2_A' : a_2_A,
            'a_2_B' : a_2_B,
            'a_2_C' : a_2_C,
            'a_2_D' : a_2_D,
            'question3': question3,
            'a_3_A' : a_3_A,
            'a_3_B' : a_3_B,
            'a_3_C' : a_3_C,
            'a_3_D' : a_3_D,
            'question4': question4,
            'a_4_A' : a_4_A,
            'a_4_B' : a_4_B,
            'a_4_C' : a_4_C,
            'a_4_D' : a_4_D,
            'question5': question5,
            'a_5_A' : a_5_A,
            'a_5_B' : a_5_B,
            'a_5_C' : a_5_C,
            'a_5_D' : a_5_D,
        }

        self.render_template('quizpage.html', params)


class GradeHandler(BaseHandler):
    def get(self):
        str_level = self.request.get('level')
        level = int(str(str_level))
        if not (self.user.level == level):
            self.render_template('youredrunk.html')
            return

        answers = self.request.get('answers')
        a_1 = self.request.get('question1')
        a_2 = self.request.get('question2')
        a_3 = self.request.get('question3')
        a_4 = self.request.get('question4')
        a_5 = self.request.get('question5')

        a_string = str(a_1) + str(a_2) + str(a_3) + str(a_4) + str(a_5)

        if a_string == answers:
            self.user.raise_level()

            currdata = self.auth.get_session_data(pop=True)
            self.auth.set_session(self.auth.store.user_to_dict(self.user), remember=True)
            self.user.put()

            header = 'Congratulations, you have passed Level ' + str(level) + '!'
            footer = 'Ready for Level ' + str(level+1) + '?'
            params = {
                'level': level,
                'header': header,
                'footer': footer,
            }
            currdata = self.auth.get_session_data(pop=True)
            self.auth.set_session(self.auth.store.user_to_dict(self.user), remember=True)
            self.user.put()
            self.render_template('grade.html', params)

        else:
            currdata = self.auth.get_session_data(pop=True)
            self.auth.set_session(self.auth.store.user_to_dict(self.user), remember=True)
            self.user.put()
            self.render_template('wronganswers.html')


config = {
  'webapp2_extras.auth': {
    'user_model': 'models.User',
    'user_attributes': ['name', 'level']
  },
  'webapp2_extras.sessions': {
    'secret_key': 'YOUR_SECRET_KEY'
  }
}

app = webapp2.WSGIApplication([
    webapp2.Route('/', MainHandler, name='home'),
    webapp2.Route('/about', AboutHandler, name='about'),
    webapp2.Route('/signup', SignupHandler),
    webapp2.Route('/<type:v|p>/<user_id:\d+>-<signup_token:.+>',
      handler=VerificationHandler, name='verification'),
    webapp2.Route('/password', SetPasswordHandler),
    webapp2.Route('/login', LoginHandler, name='login'),
    webapp2.Route('/logout', LogoutHandler, name='logout'),
    webapp2.Route('/forgot', ForgotPasswordHandler, name='forgot'),
    webapp2.Route('/authenticated', AuthenticatedHandler, name='authenticated'),
    webapp2.Route('/level', LevelHandler, name='level'),
    webapp2.Route('/dash', DashHandler, name='dash'),
    webapp2.Route('/tutorial0', TutorialHandler0, name='tutorial0'),
    webapp2.Route('/quiz0', QuizHandler0, name='quiz0'),
    webapp2.Route('/tutorial1', TutorialHandler1, name='tutorial1'),
    webapp2.Route('/quiz1', QuizHandler1, name='quiz1'),
    webapp2.Route('/tutorial2', TutorialHandler2, name='tutorial2'),
    webapp2.Route('/quiz2', QuizHandler2, name='quiz2'),
    webapp2.Route('/tutorial3', TutorialHandler3, name='tutorial3'),
    webapp2.Route('/quiz3', QuizHandler3, name='quiz3'),
    webapp2.Route('/tutorial4', TutorialHandler4, name='tutorial4'),
    webapp2.Route('/quiz4', QuizHandler4, name='quiz4'),
    webapp2.Route('/tutorial5', TutorialHandler5, name='tutorial5'),
    webapp2.Route('/quiz5', QuizHandler5, name='quiz5'),
    webapp2.Route('/grade', GradeHandler, name='grade'),

], debug=True, config=config)

logging.getLogger().setLevel(logging.DEBUG)
