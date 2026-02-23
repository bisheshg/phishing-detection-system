import json
import math
import hashlib
from uuid import uuid4
from datetime import datetime
from queue import Queue
from threading import Thread
import requests
from bs4 import BeautifulSoup
from pymisp import MISPEvent, MISPObject, MISPOrganisation
from typing import List
import re

import ail_typo_squatting
from similarius import get_website, extract_text_ressource, sk_similarity, ressource_difference, ratio

# Import shared config variables
from config import (
    red, red_user, redis_warning_list, algo_list, sessions, args,
    NUM_THREADS, CACHE_EXPIRE, CACHE_EXPIRE_SESSION,
    majestic_million, university, bank_website, parking_domain,
    parking_domain_ns, tranco, moz_top500
)

# ################### #
#  SESSION MANAGER  #
# ################### #

class Session():
    def __init__(self, url):
        """Constructor"""
        self.id = str(uuid4())
        self.url = url
        self.thread_count = NUM_THREADS
        self.jobs = Queue(maxsize=0)
        self.threads = []
        self.variations_list = list()
        self.result = list()
        self.stopped = False
        self.result_stopped = dict()
        self.add_data = False
        self.request_algo = list()
        self.catch_all = False

        self.result_algo = {key: [] for key in algo_list.keys()}
        self.result_algo['original'] = []

        self.md5Url = hashlib.md5(url.encode()).hexdigest()

        self.website = ""
        self.website_ressource = dict()

        self.list_ns = list()
        self.list_mx = list()

    def scan(self):
        """Start all worker"""
        for i in range(len(self.variations_list)):
            self.jobs.put((i, self.variations_list[i]))
        for _ in range(self.thread_count):
            worker = Thread(target=self.crawl)
            worker.daemon = True
            worker.start()
            self.threads.append(worker)

    def geoIp(self, ip):
        """Geolocation for an IP"""
        try:
            response = requests.get(f"https://ip.circl.lu/geolookup/{ip}")
            response.raise_for_status()
            response_json = response.json()
            return response_json[0]['country_info']['Country']
        except requests.exceptions.RequestException:
            return None

    def get_original_website_info(self):
        """Get website ressource of request domain"""
        data = ail_typo_squatting.dnsResolving([self.url], self.url, "", catch_all=self.catch_all)
        try:
            response = get_website(self.url)
            if not response:
                self.website, self.website_ressource = extract_text_ressource("")
            else:
                self.website, self.website_ressource = extract_text_ressource(response.text)
                if response.status_code in [200, 401]:
                    soup = BeautifulSoup(response.text, "html.parser")
                    title_tag = soup.find('title')
                    if title_tag:
                        data[self.url]['website_title'] = title_tag.get_text()
        except Exception:
            self.website, self.website_ressource = extract_text_ressource("")

        data[self.url]['website_sim'] = "100"
        data[self.url]['ressource_diff'] = "0"
        data[self.url]['ratio'] = 100

        data_keys = list(data.get(self.url, {}).keys())
        if 'A' in data_keys:
            data[self.url]['geoip'] = self.geoIp(data[self.url]['A'][0])
        elif 'AAAA' in data_keys:
            data[self.url]['geoip'] = self.geoIp(data[self.url]['AAAA'][0])

        if 'MX' in data_keys:
            data[self.url]['MX'] = [mx[:-1] for mx in data[self.url]['MX']]
        if 'NS' in data_keys:
            data[self.url]['NS'] = [ns[:-1] for ns in data[self.url]['NS']]

        data[self.url]['variation'] = "original"
        self.result[0] = data
        self.result_algo["original"].append(data)

    def get_website_info(self, variation):
        """Get all info on variation's website and compare it to orginal one."""
        website_info = {"title": "", "sim": "", "diff_score": "", "ratio": ""}
        try:
            response = get_website(variation)
            if response and response.status_code in [200, 401]:
                soup = BeautifulSoup(response.text, "html.parser")
                title_tag = soup.find('title')
                if title_tag:
                    website_info["title"] = title_tag.get_text()

                text, ressource_dict = extract_text_ressource(response.text)
                if text and self.website:
                    sim = str(sk_similarity(self.website, text))
                    website_info['sim'] = sim
                    ressource_diff = ressource_difference(self.website_ressource, ressource_dict)
                    website_info['ressource_diff'] = ressource_diff
                    website_info['ratio'] = ratio(ressource_diff, sim)
        except Exception:
            pass # Ignore errors fetching website info for variations
        return website_info

    def check_warning_list(self, data, work):
        """Mark variations present in warning lists"""
        domain_name = work[1][0]
        domain_data = data.get(domain_name, {})
        data_keys = list(domain_data.keys())
        flag_parking = False

        if majestic_million and redis_warning_list.zrank('majestic_million', domain_name) is not None:
            domain_data['majestic_million'] = True
        if parking_domain and 'A' in data_keys:
            for a in domain_data['A']:
                if redis_warning_list.zrank('parking_domains', a) is not None:
                    domain_data['parking_domains'] = True
                    domain_data['park_ip'] = True
                    flag_parking = True
                    break
        if university and redis_warning_list.zrank("university_domains", domain_name) is not None:
            domain_data['university_domains'] = True
        if bank_website and redis_warning_list.zrank("bank_domains", domain_name) is not None:
            domain_data['bank_domains'] = True
        if parking_domain_ns and not flag_parking and 'NS' in data_keys:
            if any(park in ns.lower() for ns in domain_data['NS'] for park in parking_domain_ns):
                domain_data['parking_domains'] = True
        if tranco and redis_warning_list.zrank('tranco', domain_name) is not None:
            domain_data['tranco'] = True
        if moz_top500 and redis_warning_list.zrank('moz-top500', domain_name) is not None:
            domain_data['moz-top500'] = True
        
        data[domain_name] = domain_data
        return data

    def crawl(self):
        """Threaded function for queue processing."""
        while not self.jobs.empty():
            work = self.jobs.get()
            try:
                domain_to_check, variation_type = work[1]
                flag = False

                if self.result_stopped and not args.nocache and variation_type in self.result_stopped:
                    for domain in self.result_stopped[variation_type]:
                        if list(domain.keys())[0] == domain_to_check:
                            data = self.check_warning_list(domain, work)
                            flag = True
                            break
                
                if not flag:
                    data = ail_typo_squatting.dnsResolving([domain_to_check], self.url, "", verbose=False, catch_all=self.catch_all)
                    website_info = self.get_website_info(domain_to_check)
                    data[domain_to_check].update(website_info)

                    data_keys = list(data.get(domain_to_check, {}).keys())
                    if 'A' in data_keys:
                        data[domain_to_check]['geoip'] = self.geoIp(data[domain_to_check]['A'][0])
                    elif 'AAAA' in data_keys:
                        data[domain_to_check]['geoip'] = self.geoIp(data[domain_to_check]['AAAA'][0])

                    if 'MX' in data_keys:
                        data[domain_to_check]['MX'] = [mx[:-1] for mx in data[domain_to_check]['MX']]
                        if any(any(mx_part in orig_mx for mx_part in mx.split(" ")) for mx in data[domain_to_check]['MX'] for orig_mx in self.list_mx):
                            data[domain_to_check]['mx_identified'] = True
                    
                    if 'NS' in data_keys:
                        data[domain_to_check]['NS'] = [ns[:-1] for ns in data[domain_to_check]['NS']]
                        if any(ns in self.list_ns for ns in data[domain_to_check]['NS']):
                            data[domain_to_check]['ns_identified'] = True

                    data[domain_to_check]['variation'] = variation_type
                    self.add_data = True
                    data = self.check_warning_list(data, work)

                self.result[work[0] + 1] = data
                self.result_algo[variation_type].append(data)
            except Exception:
                bad_result = {work[1][0]: {"NotExist": True}}
                self.result[work[0] + 1] = bad_result
                self.result_algo[work[1][1]].append(bad_result)
            finally:
                self.jobs.task_done()
        return True

    def status(self):
        """Status of the current queue"""
        if self.jobs.empty():
            self.stop()
        total = len(self.variations_list)
        remaining = self.jobs.qsize()
        complete = total - remaining
        registered = sum(1 for x in self.result if x and not list(x.values())[0].get("NotExist"))
        return {'id': self.id, 'total': total, 'complete': complete, 'remaining': remaining, 'registered': registered, 'stopped': self.stopped}

    def stop(self):
        """Stop the current queue and worker"""
        self.jobs.queue.clear()
        for worker in self.threads:
            worker.join(3.5)
        self.threads.clear()
        self.saveInfo()

    def domains(self):
        """Return all accessible domains"""
        return [x for x in self.result if x and not list(x.values())[0].get("NotExist")]

    def callVariations(self, data_dict):
        """Generate variations by options"""
        if "runAll" in data_dict:
            self.catch_all = True
            self.request_algo = list(algo_list.keys())
        else:
            self.request_algo = [key for key in data_dict.keys() if key in algo_list]

        for key in self.request_algo:
            fun = getattr(ail_typo_squatting, key)
            self.variations_list = fun(self.url, self.variations_list, verbose=False, limit=math.inf, givevariations=True, keeporiginal=False)

        self.result = [{} for _ in self.variations_list]
        self.result.insert(0, {})
        self.get_original_website_info()

    def dl_list(self):
        """list of variations to string"""
        return '\n'.join(variation[0] for variation in self.variations_list)

    def saveInfo(self):
        """Save session info to redis"""
        saveInfo = {
            'url': self.url, 'result_list': self.result, 'variations_list': self.variations_list,
            'stopped': self.stopped, 'md5Url': self.md5Url, 'request_algo': self.request_algo,
            'request_date': datetime.now().strftime("%Y-%m-%d %H-%M")
        }
        red.set(self.id, json.dumps(saveInfo), ex=CACHE_EXPIRE_SESSION)
        red.set(self.md5Url, 1, ex=CACHE_EXPIRE)

        for key, value in self.result_algo.items():
            if value:
                if self.add_data and red.exists(f"{self.md5Url}:{key}"):
                    try:
                        algo_redis = json.loads(red.get(f"{self.md5Url}:{key}").decode())
                        existing_domains = {list(d.keys())[0] for d in algo_redis}
                        for domain in value:
                            if list(domain.keys())[0] not in existing_domains:
                                algo_redis.append(domain)
                        red.set(f"{self.md5Url}:{key}", json.dumps(algo_redis), ex=CACHE_EXPIRE)
                    except (json.JSONDecodeError, redis.RedisError):
                        pass # Or log error
                else:
                    red.set(f"{self.md5Url}:{key}", json.dumps(value), ex=CACHE_EXPIRE)
        try:
            sessions.remove(self)
        except ValueError:
            pass # Session already removed
        del self

# ################### #
#  REDIS HELPERS    #
# ################### #

def get_session_info(sid):
    """Get session info from redis"""
    return json.loads(red.get(sid).decode())

def status_redis(sid):
    """Get session status from redis"""
    sess_info = get_session_info(sid)
    total = len(sess_info['variations_list'])
    registered = sum(1 for x in sess_info['result_list'] if x and not list(x.values())[0].get("NotExist"))
    return {'id': sid, 'total': total, 'complete': total, 'remaining': 0, 'registered': registered, 'stopped': sess_info['stopped']}

def domains_redis(sid):
    """Get identified domains list from redis"""
    sess_info = get_session_info(sid)
    return [x for x in sess_info['result_list'] if x and not list(x.values())[0].get("NotExist")]

def dl_domains(sid):
    """Get identified domains list from redis to download"""
    sess_info = get_session_info(sid)
    request_algo = sess_info.get("request_algo", [])
    request_algo.insert(0, 'original')
    result = {}
    for key in request_algo:
        if red.exists(f"{sess_info['md5Url']}:{key}"):
            loc_list = json.loads(red.get(f"{sess_info['md5Url']}:{key}").decode())
            result[key] = [x for x in loc_list if not list(x.values())[0].get("NotExist")]
            if not result[key]:
                del result[key]
    return result

def dl_list_redis(sid):
    """Get variations list from redis to download"""
    sess_info = get_session_info(sid)
    return '\n'.join(variation[0] for variation in sess_info.get("variations_list", []))

def get_algo_from_redis(data_dict, md5Url):
    """Get resolved domains list from redis"""
    request_algo = list(algo_list.keys()) if 'runAll' in data_dict else list(data_dict.keys())
    result_list = {}
    for algo in request_algo:
        if red.exists(f"{md5Url}:{algo}"):
            result_list[algo] = json.loads(red.get(f"{md5Url}:{algo}").decode())
    return result_list

def set_info(domain, request):
    """Set user info to redis"""
    ip = request.headers.get('x-forwarded-for', request.remote_addr)
    user_agent = str(request.user_agent)
    dt_string = datetime.now().strftime("%Y/%m/%d %H:%M:%S")

    if red_user.exists(ip):
        try:
            current_data = json.loads(red_user.get(ip).decode())
            if user_agent not in current_data.get('user_agent', []):
                current_data.setdefault('user_agent', []).append(user_agent)
            
            domain_found = False
            for item in current_data.get('domain', []):
                if domain in item:
                    item[domain] += 1
                    domain_found = True
                    break
            if not domain_found:
                current_data.setdefault('domain', []).append({domain: 1})

            current_data['nb_request'] = current_data.get('nb_request', 0) + 1
            current_data['last_request'] = dt_string
            red_user.set(ip, json.dumps(current_data))
        except (json.JSONDecodeError, redis.RedisError):
            pass # Or log error
    else:
        export_data = {
            'user_agent': [user_agent], 'nb_request': 1,
            'domain': [{domain: 1}], 'last_request': dt_string
        }
        red_user.set(ip, json.dumps(export_data))

def valid_ns_mx(dns):
    """Regex to validate NS and MX entry"""
    return [elem for elem in dns.replace(" ", "").split(",") if re.search(r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-\_]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$", elem)]

# ################### #
#   MISP HELPERS    #
# ################### #

def create_misp_event(sid):
    """Create a MISP event for MISP feed"""
    sess_info = get_session_info(sid)
    org = MISPOrganisation()
    org.name = "typosquatting-finder.circl.lu"
    org.uuid = "8df15512-0314-4c2a-bd00-9334ab9b59e6"
    event = MISPEvent()
    event.uuid = sid
    event.info = f"Typosquatting for: {sess_info['url']}"
    event.distribution = 0
    event.threat_level_id = 4
    event.analysis = 2
    event.Orgc = org
    return event

def feed_meta_generator(event, sid):
    """Generate MISP feed manifest"""
    manifests = event.manifest
    hashes = [f'{h},{event.uuid}' for h in event.attributes_hashes('md5')]
    red.set(f"event_manifest:{sid}", json.dumps(manifests), ex=CACHE_EXPIRE_SESSION)
    red.set(f"event_hashes:{sid}", json.dumps(hashes), ex=CACHE_EXPIRE_SESSION)

def dl_misp_feed(sid, store=True):
    """Generate MISP feed to download"""
    event = create_misp_event(sid)
    result_list = dl_domains(sid)
    sess_info = get_session_info(sid)
    domain_identified = domains_redis(sid)

    misp_object = MISPObject('typosquatting-finder', standalone=False)
    qname = misp_object.add_attribute('research-domain', value=sess_info['url'])
    qname.add_tag({'name': "typosquatting:research", 'colour': "#00730d"})
    misp_object.add_attribute('variations-number', value=len(sess_info.get("result_list", [])))
    misp_object.add_attribute('variations-found-number', value=len(domain_identified))
    event.add_object(misp_object)

    for algo, domains in result_list.items():
        for domain_info in domains:
            for domain, details in domain_info.items():
                misp_object = MISPObject('typosquatting-finder-result', standalone=False)
                qname = misp_object.add_attribute('queried-domain', value=domain)
                qname.add_tag({'name': f"typosquatting:{algo}", 'colour': "#e68b48"})
                
                for key in ['A', 'AAAA', 'MX', 'NS']:
                    if key in details:
                        for record in details[key]:
                            misp_object.add_attribute(f'{key.lower()}-record', value=record)
                
                for key in ["website_title", "website_sim", "ressource_diff", "ratio"]:
                    if key in details and details[key]:
                        misp_object.add_attribute(key.replace("_", "-"), value=details[key])
                
                event.add_object(misp_object)

    feed_event = event.to_feed()
    if store:
        red.set(f"event_json:{sid}", json.dumps(feed_event), ex=CACHE_EXPIRE_SESSION)
        return event
    return feed_event