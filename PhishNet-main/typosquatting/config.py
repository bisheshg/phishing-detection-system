import os
import json
import argparse
import configparser
import redis

# --- Argument Parsing ---
parser = argparse.ArgumentParser()
parser.add_argument("-c", "--nocache", help="Disabled caching functionality", action="store_true")
args = parser.parse_args()

# --- Configuration File Parsing ---
pathConf = './conf/conf.cfg'
if not os.path.isfile(pathConf):
    raise FileNotFoundError("[-] No conf file found at ./conf/conf.cfg")

config = configparser.ConfigParser()
config.read(pathConf)

# --- Flask Configuration ---
FLASK_URL = config.get('Flask_server', 'ip', fallback='127.0.0.1')
FLASK_PORT = config.getint('Flask_server', 'port', fallback=7005)

# --- Threading Configuration ---
NUM_THREADS = config.getint('Thread', 'num_threads', fallback=10)

# --- Redis Connections ---
try:
    red = redis.Redis(host=config.get('redis', 'host', fallback='localhost'),
                      port=config.getint('redis', 'port', fallback=6379),
                      db=config.getint('redis', 'db', fallback=0))

    red_user = redis.Redis(host=config.get('redis_user', 'host', fallback='localhost'),
                           port=config.getint('redis_user', 'port', fallback=6379),
                           db=config.getint('redis_user', 'db', fallback=1))

    redis_warning_list = redis.Redis(host=config.get('redis_warning_list', 'host', fallback='localhost'),
                                     port=config.getint('redis_warning_list', 'port', fallback=6379),
                                     db=config.getint('redis_warning_list', 'db', fallback=2))
    # Test connection
    red.ping()
    red_user.ping()
    redis_warning_list.ping()
except redis.exceptions.ConnectionError as e:
    raise ConnectionError(f"[-] Could not connect to Redis. Please ensure Redis is running and accessible. Error: {e}")


# --- Caching Configuration ---
CACHE_EXPIRE = config.getint('cache', 'expire', fallback=86400) if not args.nocache else 0
CACHE_EXPIRE_SESSION = config.getint('cache_session', 'expire', fallback=3600)

# --- Global Variables ---
# In-memory session tracking (consider removing if relying solely on Redis)
sessions = []

# Load algorithm list
try:
    with open("./etc/algo_list.json", "r") as read_json:
        algo_list = json.load(read_json)
except FileNotFoundError:
    raise FileNotFoundError("[-] Could not find ./etc/algo_list.json")

# --- Warning List Flags ---
majestic_million = redis_warning_list.exists('majestic_million')
university = redis_warning_list.exists('university_domains')
bank_website = redis_warning_list.exists('bank_website')
parking_domain = redis_warning_list.exists('parking_domains')
tranco = redis_warning_list.exists('tranco')
moz_top500 = redis_warning_list.exists('moz-top500')

try:
    parking_domain_ns = json.loads(redis_warning_list.get("parking_domains_ns").decode()) if redis_warning_list.exists('parking_domains_ns') else False
except (json.JSONDecodeError, TypeError):
    parking_domain_ns = False
