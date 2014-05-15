#!/usr/bin/env python

# (c) 2011 Rdio Inc
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# include the parent directory in the Python path
import sys,os.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# import the rdio-simple library
from rdio import Rdio
# and our example credentials
from rdio_consumer_credentials import RDIO_CREDENTIALS

from getpass import getpass

from gmusicapi import Mobileclient

web.config.smtp_server = 'smtp.mandrillapp.com'
web.config.smtp_port = 587
web.config.smtp_username = 'tinrit'
web.config.smtp_password = 'KZO8Uj-qBL9b7ji7MN18nA'
web.config.smtp_starttls = True

# import web.py
import web
import os
from rq import Queue
from worker import conn

import urllib2

urls = (
  '/', 'root',
  '/login', 'login',
  '/callback', 'callback',
  '/logout', 'logout',
  '/migrate', 'migrate',
  '/done', 'done',
)

app = web.application(urls, globals())
render = web.template.render('templates/', base='layout')
q = Queue(connection=conn)
comparing_field = 'album' #uses this field to compare the title to see if its what we are looking for. Mess with it to change the matching algorithm.


class root:
  def GET(self):
    access_token = web.cookies().get('at')
    access_token_secret = web.cookies().get('ats')
    if access_token and access_token_secret:
      rdio = Rdio(RDIO_CREDENTIALS,
        (access_token, access_token_secret))
      # make sure that we can make an authenticated call

      try:
        currentUser = rdio.call('currentUser')['result']
      except urllib2.HTTPError:
        # this almost certainly means that authentication has been revoked for the app. log out.
        raise web.seeother('/logout')

      myPlaylists = rdio.call('getPlaylists')['result']['owned']
      # print '''playlists: %s'''  % myPlaylists
      return render.index(currentUser,myPlaylists, 0)
    else:
      return render.login_rdio()

class login:
  def GET(self):
    # clear all of our auth cookies
    web.setcookie('at', '', expires=-1)
    web.setcookie('ats', '', expires=-1)
    web.setcookie('rt', '', expires=-1)
    web.setcookie('rts', '', expires=-1)
    # begin the authentication process
    rdio = Rdio(RDIO_CREDENTIALS)
    url = rdio.begin_authentication(callback_url = web.ctx.homedomain+'/callback')
    # save our request token in cookies
    web.setcookie('rt', rdio.token[0], expires=60*60*24) # expires in one day
    web.setcookie('rts', rdio.token[1], expires=60*60*24) # expires in one day
    # go to Rdio to authenticate the app
    raise web.seeother(url)

class callback:
  def GET(self):
    # get the state from cookies and the query string
    request_token = web.cookies().get('rt')
    request_token_secret = web.cookies().get('rts')
    verifier = web.input()['oauth_verifier']
    # make sure we have everything we need
    if request_token and request_token_secret and verifier:
      # exchange the verifier and request token for an access token
      rdio = Rdio(RDIO_CREDENTIALS,
        (request_token, request_token_secret))
      rdio.complete_authentication(verifier)
      # save the access token in cookies (and discard the request token)
      web.setcookie('at', rdio.token[0], expires=60*60*24*14) # expires in two weeks
      web.setcookie('ats', rdio.token[1], expires=60*60*24*14) # expires in two weeks
      web.setcookie('rt', '', expires=-1)
      web.setcookie('rts', '', expires=-1)
      # go to the home page
      raise web.seeother('/')
    else:
      # we're missing something important
      raise web.seeother('/logout')
    
class logout:
  def GET(self):
    # clear all of our auth cookies
    web.setcookie('at', '', expires=-1)
    web.setcookie('ats', '', expires=-1)
    web.setcookie('rt', '', expires=-1)
    web.setcookie('rts', '', expires=-1)
    # and go to the homepage
    raise web.seeother('/')


class migrate:
  def GET(self):
    return render.login_google("")

  def POST(self):
    i = web.input()


    api = Mobileclient()
    logged_in = api.login(i.email, i.password)
    if logged_in:
      access_token = web.cookies().get('at')
      access_token_secret = web.cookies().get('ats')
      if access_token and access_token_secret:
        # self.process_playlist(i.email, i.password, access_token, access_token_secret)
        result = q.enqueue(self.process_playlist, i.email, i.password, access_token, access_token_secret)

        return render.done()
      else:
        return 'Logged in to Google Music successfully, but you havent logged in to Rdio yet. Please go back and do that first <a href="/">Here</a>'
    else:  
      return render.login_google("Incorrect Username or Password, Try Again.")


  def process_playlist(self, email, password, access_token, access_token_secret):

    googleApi = Mobileclient()

    logged_in = googleApi.login(email, password)


    if logged_in:
      # access_token = web.cookies().get('at')
      # access_token_secret = web.cookies().get('ats')
      rdio = Rdio(RDIO_CREDENTIALS, (access_token, access_token_secret))
      playlists = rdio.call('getPlaylists', {'extras':'trackKeys'})['result']['owned']
      playlist = playlists[0]
      songs = 0
      totalSongs = 0
      # for playlist in playlists:
      tracks_string = ','.join(playlist['trackKeys'])
      songs_info = self.get_tracks_by_keys_from_rdio(tracks_string,rdio)

      print '''removing playlist by name %s''' % playlist['name']
      self.remove_playlist_by_name(playlist['name'], googleApi)
      print '''done'''
      totalSongs += len(playlist['trackKeys'])

      for key in playlist['trackKeys']:
        song = songs_info[key]
        # print '''gonna look for %s by %s on gmusic''' % (song['name'], song[comparing_field])
        track_id = self.search_song_by_name(song['name'], song[comparing_field] ,googleApi)
        # uses the existing playlist so that we won't have to create a new one.
        # print '''track %s id is %s''' % (song['name'], track_id)
        playlist_id = self.find_or_create_playlist_by_name(playlist['name'], googleApi)
        if track_id > 0:
          ++songs
          googleApi.add_songs_to_playlist(playlist_id,track_id)
          print '''added song %s to playlist %s''' % (song['name'], playlist['name'])
          # sleep(2)

      web.sendmail('migrat0r@tinrit.com', email, 'Playlist Migration Complete!', '''Your playlists have been migrated to Google Music. %s of %s songs were migrated successfully. and You're Welcome :)  \n\n\n Menan''' % (songs, totalSongs))
      return True
    else:
      return False


  def find_or_create_playlist_by_name(self,name,  api):
    all_google_playlists = api.get_all_playlists()
    found = False
    for playlist in all_google_playlists:
      if playlist['name'] == name:
        playlist_id = playlist['id']
        found = True
        # break

    if found == False:
      playlist_id = api.create_playlist(name)

    return playlist_id

  def remove_playlist_by_name(self,name, api):
    all_google_playlists = api.get_all_playlists()
    for playlist in all_google_playlists:
      if playlist['name'] == name:
        api.delete_playlist(playlist['id'])   
        # print '''deleted %s with id %s''' % (playlist['name'],playlist['id'])

  def search_song_by_name(self,name,artist_name, api):
    results = api.search_all_access(name)['song_hits']
    found = 0
    track_id = 0
    if results.count > 0:
      for track in results:
        if track['track'][comparing_field] == artist_name:
          track_id = track['track']['nid']
          # print '''found a match with id %s''' % track['track']['nid']
          ++found
          break
    return track_id

  def get_tracks_by_keys_from_rdio(self, keys, rdioApi):
    return rdioApi.call('get', {'keys' :keys})['result']





if __name__ == "__main__":
    app.run()
