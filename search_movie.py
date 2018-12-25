import httplib2
import json

# Using the moviedb api to get information a bout the movies
# for more info visit https://www.themoviedb.org/
api_key = 'b42f313de752b4082729b83599e87b3f'

# function used to search movie and return
# overview, trailer and poster if they found
def search_movie(movieName):
    name = movieName.replace(' ', '+')
    url = ('https://api.themoviedb.org/3/search/movie?api_key=%s&query=%s'
           %(api_key, name))
    h = httplib2.Http()
    response, content = h.request(url, 'GET')
    result = json.loads(content)
    if result['results']:
        overview =  result['results'][0]['overview']
        id =  result['results'][0]['id']
        trailer = get_trailer(id)
        path = result['results'][0]['poster_path']
        if path:
            poster = 'https://image.tmdb.org/t/p/w500' + path
        else:
            poster = 'https://upload.wikimedia.org/wikipedia/en/f/f9/No-image-available.jpg'
        return overview, trailer, poster
    else:
        return False

# finction used to get the trailer from themoviedb
def get_trailer(id):
    url = ('http://api.themoviedb.org/3/movie/%s/videos?api_key=%s'
           %(id, api_key))

    h = httplib2.Http()
    response, content = h.request(url, 'GET')
    result = json.loads(content)
    if result['results']:
        return result['results'][0]['key']
    return 'No trailer'
