from flask import Flask, render_template, request, jsonify
import tldextract
import hashlib

# Local imports
from config import (
    FLASK_URL, FLASK_PORT, app, algo_list, red, sessions
)
from session_manager import (
    Session, get_session_info, status_redis, domains_redis,
    dl_domains, dl_list_redis as dl_list, set_info, valid_ns_mx,
    dl_misp_feed, feed_meta_generator
)
from api import api_bp

# Register the API blueprint
app.register_blueprint(api_bp)

# ############### #
#  FLASK ROUTES   #
# ############### #

@app.route("/")
def index():
    """Home page"""
    return render_template("home_page.html", algo_list=algo_list, len_table=len(list(algo_list.keys())), keys=list(algo_list.keys()), share=0)

@app.route("/info")
def info_page():
    """Info page"""
    return render_template("info.html", algo_list=algo_list, len_table=len(list(algo_list.keys())), keys=list(algo_list.keys()))

@app.route("/about")
def about_page():
    """About page"""
    return render_template("about.html")

@app.route("/typo", methods=['POST'])
def typo():
    """Run the scan"""
    try:
        data_dict = request.json["data_dict"]
        url = data_dict["url"]

        domain_extract = tldextract.extract(url)
        # Assuming check_valid_domain is part of ail_typo_squatting, which is used in Session
        # res = ail_typo_squatting.check_valid_domain(domain_extract)
        # if res:
        #     return jsonify({'message': res}), 400
            
        if domain_extract.suffix:
            url = '.'.join(part for part in [domain_extract.subdomain, domain_extract.domain, domain_extract.suffix] if part)
            
        set_info(url, request)

        md5Url = hashlib.md5(url.encode()).hexdigest()
        session = Session(url)
        
        if "catchAll" in data_dict:
            session.catch_all = True
        if 'NS' in data_dict and data_dict['NS'].rstrip():
            session.list_ns = valid_ns_mx(data_dict['NS'])
        if 'MX' in data_dict and data_dict['MX'].rstrip():
            session.list_mx = valid_ns_mx(data_dict['MX'])

        # This logic is now handled inside the Session class, but we can check for pre-existing results
        # if red.exists(md5Url):
        #     session.result_stopped = get_algo_from_redis(data_dict, md5Url)

        session.callVariations(data_dict)
        session.scan()
        sessions.append(session) # Still using global sessions list for now
        return jsonify(session.status()), 201
    except Exception as e:
        app.logger.error(f"Error processing typosquatting request: {str(e)}")
        return jsonify({"error": "An internal error occurred"}), 500

@app.route("/stop/<sid>", methods=['POST', 'GET'])
def stop(sid):
    """Stop the <sid> queue"""
    for s in sessions:
        if s.id == sid:
            s.stopped = True
            s.stop()
            break
    return jsonify({"Stop": "Successful"}), 200

@app.route("/status/<sid>")
def status(sid):
    """Status of <sid> queue"""
    if red.exists(sid):
        return jsonify(status_redis(sid))
    for s in sessions:
        if s.id == sid:
            return jsonify(s.status())
    return jsonify({'message': 'Scan session not found'}), 404

@app.route("/domains/<sid>")
def domains(sid):
    """Return all accessible domains"""
    if red.exists(sid):
        return jsonify(domains_redis(sid))
    for s in sessions:
        if s.id == sid:
            return jsonify(s.domains())
    return jsonify({'message': 'Scan session not found'}), 404

@app.route("/download/<sid>/json")
def download_json(sid):
    """Give the result as json format"""
    if red.exists(sid):
        sess_info = get_session_info(sid)
        return jsonify(dl_domains(sid)), 200, {'Content-Disposition': f'attachment; filename=typo-squatting-{sess_info["url"]}.json'}
    return jsonify({'message': 'Scan session not found'}), 404

@app.route("/download/<sid>/list")
def download_list(sid):
    """Give the list of variations"""
    if red.exists(sid):
        sess_info = get_session_info(sid)
        return dl_list(sid), 200, {'Content-Type': 'text/plain', 'Content-Disposition': f'attachment; filename={sess_info["url"]}-variations.txt'}
    return jsonify({'message': 'Scan session not found'}), 404

@app.route("/<sid>")
def share(sid):
    """Share a research"""
    return render_template("home_page.html", algo_list=algo_list, len_table=len(list(algo_list.keys())), keys=list(algo_list.keys()), share=sid)

@app.route("/share/<sid>")
def share_info(sid):
    """Get share info from redis"""
    if red.exists(sid):
        sess_info = get_session_info(sid)
        return sess_info['url'], 200
    return jsonify({'message': 'Scan session not found'}), 404

# ############# #
#  MISP ROUTES  #
# ############# #

@app.route("/download/<sid>/misp-feed")
def download_misp_feed_route(sid):
    """Give the list of variations"""
    if red.exists(sid):
        event = dl_misp_feed(sid, store=True)
        feed_meta_generator(event, sid)
        html = f'<a href="/download/{sid}/misp-feed/{event.uuid}.json">{event.uuid}.json</a><br />'
        html += f'<a href="/download/{sid}/misp-feed/hashes.csv">hashes.csv</a><br />'
        html += f'<a href="/download/{sid}/misp-feed/manifest.json">manifest.json</a>'
        return html
    return jsonify({"message": "Session not found"}), 404

@app.route("/download/<sid>/misp-feed/<file>")
def download_misp_file(sid, file):
    """Download a specific MISP feed file"""
    # This logic can be further simplified, but keeping for now
    if file == 'hashes.csv' and red.exists(f"event_hashes:{sid}"):
        return jsonify(json.loads(red.get(f"event_hashes:{sid}").decode())), 200
    elif file == 'manifest.json' and red.exists(f"event_manifest:{sid}"):
        return jsonify(json.loads(red.get(f"event_manifest:{sid}").decode())), 200
    elif red.exists(f"event_json:{sid}"):
        event = json.loads(red.get(f"event_json:{sid}").decode())
        if file.split('.')[0] == event['Event']['uuid']:
            return jsonify(event), 200
    return jsonify({'message': 'File not found'})

@app.route("/download/<sid>/misp-json")
def download_misp_json(sid):
    """Download MISP feed as json format"""
    if red.exists(sid):
        event = dl_misp_feed(sid, store=False)
        return jsonify(event), 200, {'Content-Disposition': f"attachment; filename={event['Event']['uuid']}.json"}
    return jsonify({'message': 'Scan session not found'}), 404

if __name__ == "__main__":
    app.run(host=FLASK_URL, port=FLASK_PORT)