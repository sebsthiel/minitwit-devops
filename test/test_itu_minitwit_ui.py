"""
To run this test with a visible browser, the following dependencies have to be setup:

  * `pip install selenium`
  * `pip install pymongo`
    * `pip install pytest`
    * `pip install psycopg2-binary`
  * `wget https://github.com/mozilla/geckodriver/releases/download/v0.32.0/geckodriver-v0.32.0-linux64.tar.gz`
  * `tar xzvf geckodriver-v0.32.0-linux64.tar.gz`
  * After extraction, the downloaded artifact can be removed: `rm geckodriver-v0.32.0-linux64.tar.gz`

The application that it tests is the version of _ITU-MiniTwit_ that you got to know during the exercises on Docker:
https://github.com/itu-devops/flask-minitwit-mongodb/tree/Containerize (*OBS*: branch Containerize)

```bash
$ git clone https://github.com/HelgeCPH/flask-minitwit-mongodb.git
$ cd flask-minitwit-mongodb
$ git switch Containerize
```

After editing the `docker-compose.yml` file file where you replace `youruser` with your respective username, the
application can be started with `docker-compose up`.

Now, the test itself can be executed via: `pytest test_itu_minitwit_ui.py`.
"""


from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options
import os
import shutil
import psycopg2


GUI_URL = "http://localhost:5001/register"
DB_PATH = os.getenv("DATABASE_PATH") or os.getenv("DATABASE_PATH_HOST")
GECKODRIVER_PATH = os.getenv("GECKODRIVER_PATH", "geckodriver")
FIREFOX_BIN = os.getenv("FIREFOX_BIN") or shutil.which("firefox")

if not DB_PATH:
    raise RuntimeError("DATABASE_PATH must be set to a PostgreSQL DSN")


def get_connection():
    try:
        return psycopg2.connect(
            database="minitwit_test",
            user="test",
            password="test",
            host="127.0.0.1",
            port=5432,
        )
    except:
        return False
conn = get_connection()
if conn:
    print("Connection to the PostgreSQL established successfully.")
else:
    print("Connection to the PostgreSQL encountered and error.")



def _register_user_via_gui(driver, data):
    driver.get(GUI_URL)

    wait = WebDriverWait(driver, 5)
    buttons = wait.until(EC.presence_of_all_elements_located((By.CLASS_NAME, "actions")))
    input_fields = driver.find_elements(By.TAG_NAME, "input")

    for idx, str_content in enumerate(data):
        input_fields[idx].send_keys(str_content)
    input_fields[4].send_keys(Keys.RETURN)

    wait = WebDriverWait(driver, 5)
    flashes = wait.until(EC.presence_of_all_elements_located((By.CLASS_NAME, "flashes")))

    return flashes


def _new_driver():
    firefox_options = Options()
    firefox_options.add_argument("--headless")
    if FIREFOX_BIN:
        firefox_options.binary_location = FIREFOX_BIN
    firefox_service = Service(executable_path=GECKODRIVER_PATH)
    return webdriver.Firefox(service=firefox_service, options=firefox_options)


def _get_user_by_name(conn, name):
        with conn.cursor() as cur:
            cur.execute('SELECT username FROM "user" WHERE username = %s', (name,))
            row = cur.fetchone()
            return row[0] if row else None
   

def test_register_user_via_gui():
    """
    This is a UI test. It only interacts with the UI that is rendered in the browser and checks that visual
    responses that users observe are displayed.
    """
    with _new_driver() as driver:
        generated_msg = _register_user_via_gui(driver, ["Me", "me@some.where", "secure123", "secure123"])[0].text
        expected_msg = "You were successfully registered and can login now"
        assert generated_msg == expected_msg

    # cleanup, make test case idempotent
   
def _delete_user_by_name(conn, name):
        with conn.cursor() as cur:
            cur.execute('DELETE FROM "user" WHERE username = %s', (name,))
        conn.commit()

def test_register_user_via_gui_and_check_db_entry():
    """
    This is an end-to-end test. Before registering a user via the UI, it checks that no such user exists in the
    database yet. After registering a user, it checks that the respective user appears in the database.
    """
    assert _get_user_by_name(conn, "Me") is None
    with _new_driver() as driver:
        generated_msg = _register_user_via_gui(driver, ["Me", "me@some.where", "secure123", "secure123"])[0].text
        expected_msg = "You were successfully registered and can login now"
        assert generated_msg == expected_msg

        assert _get_user_by_name(conn, "Me") == "Me"

        # cleanup, make test case idempotent
        _delete_user_by_name(conn, "Me")
