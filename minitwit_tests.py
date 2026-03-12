import os
from time import sleep

import requests
from bs4 import BeautifulSoup


FRONTEND_URL = os.getenv("FRONTEND_URL", "http://minitwit-app:5001")

while True:
    # Wait for service DNS and DB readiness before running tests.
    try:
        r = requests.get(FRONTEND_URL)
        if "mysql.connector.errors.InterfaceError" in r.text:
            print("Waiting another 5s for DB to be initialized...")
            sleep(5)
        else:
            break
    except requests.RequestException:
        print("Waiting another 5s for frontend to be reachable...")
        sleep(5)


def test_thirty_msgs_on_frontpage():
    r = requests.get(FRONTEND_URL)
    soup = BeautifulSoup(r.content, "html.parser")
    tweets = soup.find("ul", {"class": "messages"}).findAll("strong")

    assert len(tweets) == 30


def test_first_tweeters_on_frontpage():
    r = requests.get(FRONTEND_URL)
    soup = BeautifulSoup(r.content, "html.parser")
    tweeters = soup.find("ul", {"class": "messages"}).findAll("a")

    assert tweeters[0].text == "Johnnie Lesso"
    assert tweeters[1].text == "Sharmaine Abdelrahman"
    assert tweeters[2].text == "Dominga Barcenas"
    assert tweeters[3].text == "Kerry Passer"