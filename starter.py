import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Catalog, Base, Item, User

Base = declarative_base()

engine = create_engine('sqlite:///catalogmovi.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

user = User(name='moataz',email='motazbellahhamdy@gmail.com')
session.add(user)
session.commit()

genres = ['Action', 'Comedy', 'Crime', 'Drama', 'Historical', 'Romance', 'Sci-Fi']

for genre in genres:
    type = Catalog(name=genre)
    session.add(type)
    session.commit()

item1 = Item(name="Logan", user_id=1,catalog_id=1)
session.add(item1)
session.commit()

item2 = Item(name="The Hangover", user_id=1,catalog_id=2)
session.add(item2)
session.commit()

item3 = Item(name="Pulp Fiction", user_id=1,catalog_id=3)
session.add(item3)
session.commit()

item4 = Item(name="Shawshank Redemption", user_id=1,catalog_id=4)
session.add(item4)
session.commit()

item5 = Item(name="Dunkirk", user_id=1,catalog_id=5)
session.add(item5)
session.commit()

item6 = Item(name="About Time", user_id=1,catalog_id=6)
session.add(item6)
session.commit()

item7 = Item(name="The Martian", user_id=1,catalog_id=7)
session.add(item7)
session.commit()
