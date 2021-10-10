# coding=utf-8
import pickle

cache = {}


def save():
    with open("save.pickle", "wb") as write_file:
        pickle.dump(cash, write_file)


def load():
    global cash, default_ttl
    with open("save.pickle", "rb") as read_file:
        cash = pickle.load(read_file)