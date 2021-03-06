#!/usr/bin/env python2.7

"""
Columbia W4111 Intro to databases
Example webserver

To run locally

    python server.py

Go to http://localhost:8111 in your browser


A debugger such as "pdb" may be helpful for debugging.
Read about it online.
"""

import os
from sqlalchemy import *
from sqlalchemy.pool import NullPool
from flask import Flask, request, render_template, g, redirect, Response
from serv_backend import *
from dateutil import parser as dparse

# import os
import base64
import pickle
import datetime

# from sqlalchemy import *
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

tmpl_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
app = Flask(__name__, template_folder=tmpl_dir)

#########################################################################
#
# SERVER CODE START FROM HERE!
#
# The following uses the postgresql test.db -- you can use this for debugging purposes
# However for the project you will need to connect to your Part 2 database in order to use the
# data
#
# XXX: The URI should be in the format of: 
#
#     postgresql://USER:PASSWORD@<IP_OF_POSTGRE_SQL_SERVER>/postgres
#
# For example, if you had username ewu2493, password foobar, then the following line would be:
#
#     DATABASEURI = "postgresql://ewu2493:foobar@<IP_OF_POSTGRE_SQL_SERVER>/postgres"
#
# Swap out the URI below with the URI for the database created in part 2
DATABASEURI = "postgresql://jf2966:jms4e@104.196.175.120/postgres"


#
# This line creates a database engine that knows how to connect to the URI above
#
engine = create_engine(DATABASEURI)

execfile('serv_backend.py')
#
# START SQLITE SETUP CODE
#
# after these statements run, you should see a file test.db in your webserver/ directory
# this is a sqlite database that you can query like psql typing in the shell command line:
# 
#     sqlite3 test.db
#
# The following sqlite3 commands may be useful:
# 
#     .tables               -- will list the tables in the database
#     .schema <tablename>   -- print CREATE TABLE statement for table
# 
# The setup code should be deleted once you switch to using the Part 2 postgresql database
#
# engine.execute("""DROP TABLE IF EXISTS test;""")
# engine.execute("""CREATE TABLE IF NOT EXISTS test (
#   id serial,
#   name text
# );""")
# engine.execute("""INSERT INTO test(name) VALUES ('grace hopper'), ('alan turing'), ('ada lovelace');""")
#
# END SQLITE SETUP CODE
#


class User_info():
  def __init__(self):
    self.username=''
    self.passwowd=''
    self.login=False
    self.emDisplayed=[]
    self.conDisplayed=[]
    self.evtDisplayed=[]
    self.all_evt=[]

user=User_info()
    


@app.before_request
def before_request():
  """
  This function is run at the beginning of every web request 
  (every time you enter an address in the web browser).
  We use it to setup a database connection that can be used throughout the request

  The variable g is globally accessible
  """
  try:
    g.conn = engine.connect()
  except:
    print "uh oh, problem connecting to database"
    import traceback; traceback.print_exc()
    g.conn = None

@app.teardown_request
def teardown_request(exception):
  """
  At the end of the web request, this makes sure to close the database connection.
  If you don't the database could run out of memory!
  """
  try:
    g.conn.close()
  except Exception as e:
    pass


#
# @app.route is a decorator around index() that means:
#   run index() whenever the user tries to access the "/" path using a GET request
#
# If you wanted the user to go to e.g., localhost:8111/foobar/ with POST or GET then you could use
#
#       @app.route("/foobar/", methods=["POST", "GET"])
#
# PROTIP: (the trailing / in the path is important)
# 
# see for routing: http://flask.pocoo.org/docs/0.10/quickstart/#routing
# see for decorators: http://simeonfranklin.com/blog/2012/jul/1/python-decorators-in-12-steps/
#
@app.route('/')
def index():
  """
  request is a special object that Flask provides to access web request information:

  request.method:   "GET" or "POST"
  request.form:     if the browser submitted a form, this contains the data in the form
  request.args:     dictionary of URL arguments e.g., {a:1, b:2} for http://localhost?a=1&b=2

  See its API: http://flask.pocoo.org/docs/0.10/api/#incoming-request-data
  """

  # DEBUG: this is debugging code to see what request looks like
  print request.args


  #
  # example of a database query
  #
  cursor = g.conn.execute("SELECT email_address FROM users")
  names = []
  for result in cursor:
    names.append(result['email_address'])  # can also be accessed using result[0]
  cursor.close()

  #
  # Flask uses Jinja templates, which is an extension to HTML where you can
  # pass data to a template and dynamically generate HTML based on the data
  # (you can think of it as simple PHP)
  # documentation: https://realpython.com/blog/python/primer-on-jinja-templating/
  #
  # You can see an example template in templates/index.html
  #
  # context are the variables that are passed to the template.
  # for example, "data" key in the context variable defined below will be 
  # accessible as a variable in index.html:
  #
  #     # will print: [u'grace hopper', u'alan turing', u'ada lovelace']
  #     <div>{{data}}</div>
  #     
  #     # creates a <div> tag for each element in data
  #     # will print: 
  #     #
  #     #   <div>grace hopper</div>
  #     #   <div>alan turing</div>
  #     #   <div>ada lovelace</div>
  #     #
  #     {% for n in data %}
  #     <div>{{n}}</div>
  #     {% endfor %}
  #
  context = dict(data = names)


  #
  # render_template looks in the templates/ folder for files.
  # for example, the below file reads template/index.html
  #
  return render_template("index.html", **context)

# Example of adding new data to the database
# @app.route('/add', methods=['POST'])
# def add():
#   name = request.form['name']
#   print name
#   cmd = 'INSERT INTO test(name) VALUES (:name1), (:name2)';
#   g.conn.execute(text(cmd), name1 = name, name2 = name);
#   return redirect('/')

@app.route('/register', methods=['POST'])
def register():
  username = request.form['username']
  password = request.form['password']
  user.username=username
  user.password=password
  print user.username
  print user.password
  create_user(user.username, user.password)
  return redirect('/')


@app.route('/login', methods=['POST'])
def login():
    user.username = request.form['username']
    user.password = request.form['password']
    print user.username
    print user.password
    authenticate(user.username, user.password)
    return redirect('/mainpage')

@app.route('/logout', methods=['POST'])
def logout():
    user=None
    return redirect('/')
    

@app.route('/mainpage')
def mainpage():
  print 'mainpage'
  em_folders = get_email_folders(user.username,user.password)
  con_folders = get_contacts_folders(user.username,user.password)
  cal_folders = get_calendar_folders(user.username,user.password)
  
  email_ret = user.emDisplayed
  evt_ret = user.evtDisplayed
  con_ret = user.conDisplayed
  all_evt = user.all_evt

  return render_template("mainpage.html", em_folders=em_folders,
    con_folders=con_folders, cal_folders=cal_folders, 
    username=user.username, email_ret=email_ret, evt_ret=evt_ret,
    con_ret=con_ret,all_evt=all_evt)


@app.route('/create_email', methods=['POST'])
def create_email():
    context = dict(username=user.username)
    return render_template("new_email.html", **context)

'''create new folders '''
@app.route('/create_email_folder', methods=['POST'])
def create_email_folder():
    fname = request.form['em_folder_name']
    print fname
    add_email_folder(user.username,user.password,fname)
    return redirect('/mainpage')


@app.route('/create_contact_folder', methods=['POST'])
def create_contact_folder():
    cname = request.form['con_folder_name']
    print cname
    add_contacts_folder(user.username,user.password,cname)
    return redirect('/mainpage')


@app.route('/create_calender_folder', methods=['POST'])
def create_calender_folder():
    cname = request.form['cal_folder_name']
    print cname
    add_calendar_folder(user.username,user.password,cname)
    return redirect('/mainpage')

@app.route('/create_contact', methods=['POST'])
def create_contact():
    # con_folder_fid=19 #TODO
    con_name = request.form['contact_name']
    con_addr = request.form['contact_addr']
    con_phone_number = request.form['contact_phone_number']
    con_em_addr = request.form['contact_em_addr']
    con_folder_name=request.form['contact_folder']
    useremail = "%s@securemail.com" % user.username
    if  len(get_fid(useremail, con_folder_name)) > 0:
      con_fid = get_fid(useremail, con_folder_name)[0]
      add_contact(user.username, user.password, con_fid, con_name, con_addr, con_phone_number, con_em_addr)
      return redirect('/mainpage')
    else: 
      return redirect('/404')
    

@app.route('/send_new_email', methods=['POST'])
def send_new_email():
  print "SEND EMAIL"
  dstusername=request.form['receiver']
  text=request.form['text']
  send_email(user.username,user.password,dstusername,text)
  return redirect('/mainpage')


@app.route('/delete_draft', methods=['POST'])
def delete_draft():
  print "DELETE DRAFT"
  return redirect('/mainpage')

@app.route('/list_email/<int:fid>', methods=['POST'])
def list_email(fid):
  print "list_email"
  user.emDisplayed=list_email_in_folder(user.username, user.password, fid)
  return redirect('/mainpage')

@app.route('/list_contacts/<int:fid>', methods=['POST'])
def list_contacts(fid):
  print "list_contacts"
  print fid
  user.conDisplayed=get_contacts_in_folder(user.username, user.password, fid) 
  print user.conDisplayed
  return redirect('/mainpage')

@app.route('/list_events/<int:fid>', methods=['POST'])
def list_events(fid):
  print "list_events"
  user.evtDisplayed=get_events_in_folder(user.username, user.password, fid)
  return redirect('/mainpage')

@app.route('/list_all_events', methods=['POST'])
def list_all_events():
  print "list_all_events"
  user.all_evt=get_my_events(user.username, user.password)
  return redirect('/mainpage')
  
@app.route('/create_event', methods=['POST'])
def create_event():
    folder = request.form['event_folder']
    name = request.form['event_name']
    place = request.form['event_name']
    begin = request.form['event_begin']
    end = request.form['event_end']
    participants = request.form['event_part']
    
    #figure out which folder
    folders = get_calendar_folders(user.username, user.password)
    fid = -1
    for f in folders:
        if f[1].encode('ascii') == folder.encode('ascii'):
            fid = f[0]
            break
    begin = dparse.parse(begin)
    end = dparse.parse(end)
    psplit = participants.split(',')
    evid = add_event(user.username, user.password, fid, begin, end, name, place, 0, datetime.datetime.now())
    for p in psplit:
        add_participant_to_event(user.username, user.password, evid, p.strip())
    add_participant_to_event(user.username, user.password, evid, user.username)
    
    return redirect('/mainpage')

@app.route('/create_mailinglist', methods=['POST'])
def create_ml():
    name = request.form['ml_name']
    members = request.form['ml_part']
    
    #figure out which folder
    create_mailinglist(user.username, user.password, name)
    
    psplit = members.split(',')
    for p in psplit:
        add_user_to_mailinglist(user.username, user.password, name, p)
    return redirect('/mainpage')
    

@app.route('/404')
def page_not_found():
    return "404 NOT FOUND"

if __name__ == "__main__":
  import click

  @click.command()
  @click.option('--debug', is_flag=True)
  @click.option('--threaded', is_flag=True)
  @click.argument('HOST', default='0.0.0.0')
  @click.argument('PORT', default=8111, type=int)
  def run(debug, threaded, host, port):
    """
    This function handles command line parameters.
    Run the server using

        python server.py

    Show the help text using

        python server.py --help

    """

    HOST, PORT = host, port
    print "running on %s:%d" % (HOST, PORT)
    app.run(host=HOST, port=PORT, debug=debug, threaded=threaded)


  run()
