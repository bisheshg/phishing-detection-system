from flask import Blueprint, request, jsonify
from flask_restx import Api, Resource
import hashlib
import tldextract

# Local imports
from config import red, sessions, algo_list
from session_manager import (
    Session, get_session_info, status_redis, domains_redis, set_info, get_algo_from_redis
)
from ail_typo_squatting import check_valid_domain

# Create a Blueprint for the API
api_bp = Blueprint('api_v1', __name__, url_prefix='/api/v1')
api = Api(api_bp, title='AIL Typosquatting API', 
          description='API to submit and query typosquatting scans.',
          doc='/doc/')

@api.route('/scan/<string:url>')
@api.doc(description='Start a new scan for the given URL.', params={'url': 'The URL to scan'})
class ScanUrl(Resource):
    def get(self, url):
        """
        Starts a new typosquatting scan. 
        Specify algorithms as query params (e.g., ?addition&charom). 
        Defaults to all algorithms if none are specified.
        """
        domain_extract = tldextract.extract(url)
        res = check_valid_domain(domain_extract)
        if res:
            return {'message': f'Invalid domain: {res}'}, 400
            
        if domain_extract.suffix:
            url = '.'.join(part for part in [domain_extract.subdomain, domain_extract.domain, domain_extract.suffix] if part)
        
        set_info(url, request)

        data_dict = dict(request.args)
        if not data_dict:
            data_dict['runAll'] = ''

        md5Url = hashlib.md5(url.encode()).hexdigest()
        session = Session(url)

        if red.exists(md5Url):
            session.result_stopped = get_algo_from_redis(data_dict, md5Url)

        session.callVariations(data_dict)
        session.scan()
        sessions.append(session)

        return jsonify({'sid': session.id})

@api.route('/status/<string:sid>')
@api.doc(description='Get the status of a running scan.', params={'sid': 'The Session ID of the scan'})
class Status(Resource):
    def get(self, sid):
        """Returns the current status of the scan queue."""
        if red.exists(sid):
            return jsonify(status_redis(sid))
        for s in sessions:
            if s.id == sid:
                return jsonify(s.status())
        return {'message': 'Scan session not found'}, 404

@api.route('/domains/<string:sid>')
@api.doc(description='Get the results of a scan.', params={'sid': 'The Session ID of the scan'})
class Domains(Resource):
    def get(self, sid):
        """Returns the list of identified typosquatting domains."""
        if red.exists(sid):
            return jsonify(domains_redis(sid))
        for s in sessions:
            if s.id == sid:
                return jsonify(s.domains())
        return {'message': 'Scan session not found'}, 404

@api.route('/stop/<string:sid>')
@api.doc(description='Stop a running scan.', params={'sid': 'The Session ID of the scan'})
class Stop(Resource):
    def get(self, sid):
        """Stops a running scan session."""
        for s in sessions:
            if s.id == sid:
                s.stopped = True
                s.stop()
                return jsonify({"status": "Stop request sent"}), 200
        return {'message': 'Active scan session not found'}, 404