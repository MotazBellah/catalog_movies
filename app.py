from flask import (Flask, render_template, request,
                   redirect, url_for, jsonify, flash)
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Catalog, Base, Item, User
 # Using search_movie function to get the info
from search_movie import search_movie

from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests


engine = create_engine('sqlite:///catalogmovi.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase +
                    string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)

    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        print response
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        j = json.dumps('Current user is already connected.')
        response = make_response(j, 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    # login_session['username'] = data['name']
    # login_session['picture'] = data['picture']
    login_session['username'] = data.get('name', '')
    login_session['picture'] = data.get('picture', '')
    login_session['email'] = data['email']

    user_id = getUserID(data['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    flash("you are now logged in as %s" % login_session['username'])
    return redirect(url_for('showCatalog'))


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one_or_none()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one_or_none()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one_or_none()
        return user.id
    except:
        return None


@app.route('/gdisconnect')
def gdisconnect():
        # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return redirect(url_for('showCatalog'))
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# Using this function to get info from search_movie
def getMovieInf(movieName):
    movie = search_movie(movieName)
    # if movie found return the info about it
    if movie:
        overview = movie[0]
        trailer = movie[1]
        poster = movie[2]
        return trailer, overview, poster
    return False


@app.route('/')
@app.route('/catalogs')
def showCatalog():
    catalogs = session.query(Catalog).all()
    if 'username' not in login_session:
        return render_template('catalogs.html', catalogs=catalogs)
    else:
        return render_template('catalogsloggedin.html', catalogs=catalogs)


@app.route('/catalogs/JSON')
def showCatalogJSON():
    catalogs = session.query(Catalog).all()
    return jsonify(catalogs=[i.serialize for i in catalogs])


@app.route('/catalogs/<catalog_name>/movies/JSON')
def showItemJSON(catalog_name):
    catalog = session.query(Catalog).filter_by(name=catalog_name).one()
    items = session.query(Item).filter_by(catalog_id=catalog.id).all()
    return jsonify(Movies=[i.serialize for i in items])


@app.route('/catalogs/<catalog_name>/<item_name>/JSON')
def showItemInfoJSON(catalog_name, item_name):
    item = session.query(Item).filter_by(name=item_name).first()
    return jsonify(Movie=item.serialize)


@app.route('/catalogs/<catalog_name>')
@app.route('/catalogs/<catalog_name>/movies')
def showItem(catalog_name):
    poster = []
    catalogs = session.query(Catalog).all()
    catalog_id = session.query(Catalog).filter_by(name=catalog_name).first().id
    catalog = session.query(Catalog).filter_by(name=catalog_name).one()

    # Check if the user in login session
    # return the movies thay belong to each user
    if 'user_id' in login_session:
        user_id = login_session['user_id']
        items = (session.query(Item)
                 .filter_by(catalog_id=catalog.id)
                 .filter_by(user_id=user_id)
                 .all()
                 )
    # If not just return the welcome page
    else:
        items = (session.query(Item)
                 .filter_by(catalog_id=catalog.id)
                 .all()
                 )
        return render_template('welcome.html', catalogs=catalogs)

    # To avoid errors check if thier items found
    # get the movie info and create a list of poster
    # pass this poster list to template to display it
    if items:
        for item in items:
            movie = getMovieInf(item.name)
            poster.append(movie[2])

    if 'username' not in login_session:
        return render_template('items.html', items=items, catalog=catalog,
                               catalogs=catalogs, catalog_name=catalog_name,
                               x=len(items), poster=poster)
    else:
        return render_template('itemsloggedin.html',
                               items=items, catalog=catalog,
                               catalogs=catalogs, catalog_name=catalog_name,
                               x=len(items), poster=poster)


@app.route('/catalogs/<catalog_name>/<item_name>')
def showItemInfo(catalog_name, item_name):
    # Using moviesDB to get the info
    movie = getMovieInf(item_name)
    catalogs = session.query(Catalog).all()
    items = session.query(Item).filter_by(name=item_name).first()
    catalog = session.query(Catalog).filter_by(id=items.catalog_id).first()
    # Check if info found
    # then, get trailer and overview
    if movie:
        # Get the overview
        overview = movie[1]
        # Pass the key to youtube embed to show the trailer
        m = movie[0]

    if 'username' not in login_session:
        return render_template('itemInfo.html', items=items,
                               overview=overview, m=m, catalogs=catalogs)
    else:
        return render_template('itemInfologgedin.html',
                               items=items,overview=overview,
                               m=m, catalogs=catalogs)


@app.route('/catalogs/<catalog_name>/movies/new', methods=['GET', 'POST'])
def newItem(catalog_name):
    if 'username' not in login_session:
        return redirect('/login')
    catalog_id = session.query(Catalog).filter_by(name=catalog_name).first().id
    if request.method == 'POST':
        # Check if the movie exsit
        # Or user type the movie name incorrectly
        if getMovieInf(request.form['name']):
            # Get discription and save it in DB
            description = 'No description for this movie'
            if getMovieInf(request.form['name'])[1]:
                description = getMovieInf(request.form['name'])[1]
            newItem = Item(name=request.form['name'], description=description,
                           type=catalog_name, catalog_id=catalog_id,
                           user_id=login_session['user_id'])

            session.add(newItem)
            session.commit()
            flash("New Movie added!")
            return redirect(url_for('showItem', catalog_name=catalog_name))
        # Notify the user
        else:
            flash("This movie is not exist :( , please check your spelling!")
            return redirect(url_for('newItem', catalog_name=catalog_name))
    else:
        return render_template('newItem.html', catalog_name=catalog_name)


@app.route('/catalogs/<catalog_name>/<item_name>/edit',
           methods=['GET', 'POST'])
def editItem(catalog_name, item_name):
    if 'username' not in login_session:
        return redirect('/login')
    catalogs = session.query(Catalog).all()
    editedItem = (session.query(Item).filter_by(user_id=login_session['user_id'])
                                     .filter_by(name=item_name)
                                     .first()
                                     )
    if login_session['user_id'] != editedItem.user_id:
        flash('''You are not authorized to update the movies list,
              Please login first!''' )")
        return render_template('notAuthorized.html', catalogs=catalogs)

    if request.method == 'POST':
        # if name changed updatemthe movie name in database
        if request.form['name']:
            editedItem.name = request.form['name']

        # if genre changed, update the movie type in DB
        if request.form['genre'] != 'Choose...':
            editedCatalog = str(request.form.get('genre'))
            editedItem.type = editedCatalog
            catalog_id = (session.query(Catalog)
                          .filter_by(name=editedCatalog)
                          .first()
                          .id
                          )
            editedItem.catalog_id = catalog_id

        session.add(editedItem)
        session.commit()
        flash("Movie has been edited!")
        return redirect(url_for('showItem', catalog_name=catalog_name))
    else:
        return render_template('editItem.html', item_name=item_name,
                               catalogs=catalogs, catalog_name=catalog_name,
                               item=editedItem)


@app.route('/catalogs/<catalog_name>/<item_name>/delete',
           methods=['GET', 'POST'])
def deleteItem(catalog_name, item_name):
    if 'username' not in login_session:
        return redirect('/login')
    item = (session.query(Item).filter_by(user_id=login_session['user_id'])
                               .filter_by(name=item_name)
                               .first()
                               )
    if login_session['user_id'] != item.user_id:
        catalogs = session.query(Catalog).all()
        flash('''You are not authorized to update the movies list,
              Please login first!''' )
        return render_template('notAuthorized.html', catalogs=catalogs)

    if request.method == 'POST':
        session.delete(item)
        session.commit()
        flash("Movie has been deleted!")
        return redirect(url_for('showItem', catalog_name=catalog_name))
    else:
        return render_template('deleteItem.html',
                               item_name=item_name, catalog_name=catalog_name,
                               item=item)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
