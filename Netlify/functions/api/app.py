import os
import pickle
from flask import Flask, request, render_template
import pandas as pd
import re
from bs4 import BeautifulSoup
import urllib
import joblib
import socket
import whois
import requests
from urllib.parse import urlparse

# Load the trained model
model_path = 'model/phishing_model.pkl'
with open(model_path, 'rb') as model_file:
    model = joblib.load(model_file)

# Feature extraction function (example)
def extract_features(url):
    # Parse the URL
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or ""
    path = parsed_url.path or ""

    # Feature extraction
    try:
      soup = BeautifulSoup(urllib.request.urlopen("https://website.informer.com/" + url).read(), "xml")
      search = soup.find('h3',class_ = "intro__trust-title").text.strip()
      trust = 0
    except:
      trust = 1
    if trust == 0:
      if '://' in url:
          protocol, rest_of_url = url.split('://', 1)
      else:
          protocol = ''
          rest_of_url = url
      if not rest_of_url.startswith('www.'):
          rest_of_url = 'www.' + rest_of_url
      # Reconstruct the URL with 'www.'
      if protocol:
          url = f"{protocol}://{rest_of_url}"
      else:
          url = rest_of_url
    length_url = len(url)
    length_hostname = len(hostname)

    ip = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0
    nb_dots = url.count('.')
    nb_hyphens = url.count('-')
    nb_at = url.count('@')
    nb_qm = url.count('?')
    nb_and = url.count('&')
    nb_eq = url.count('=')
    nb_slash = url.count('/')
    nb_semicolumn = url.count(';')
    if trust == 1:
      nb_www = url.lower().count('www')
    else:
      nb_www = 1
    nb_com = url.lower().count('.com')

    https_token = 0 if 'https' in hostname else 1
    ratio_digits_url = sum(c.isdigit() for c in url) / length_url
    ratio_digits_host = sum(c.isdigit() for c in hostname) / length_hostname

    tld_in_subdomain = 0 if re.search(r'\.(com|net|org|edu|gov|mil)\.', hostname) else 1
    abnormal_subdomain = 1 if hostname.count('.') > 1 else 0
    nb_subdomains = hostname.count('.') - 1 if abnormal_subdomain else 0
    prefix_suffix = 1 if '-' in hostname else 0

    shortening_service = 1 if re.search(r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net", url) else 0

    words_raw = re.split(r'\W+', url)
    length_words_raw = len(words_raw)
    shortest_word_host = min((len(word) for word in hostname.split('.')), default=0)
    longest_words_raw = max((len(word) for word in words_raw), default=0)
    longest_word_host = max((len(word) for word in hostname.split('.')), default=0)
    longest_word_path = max((len(word) for word in path.split('/')), default=0)
    avg_words_raw = sum(len(word) for word in words_raw) / length_words_raw if length_words_raw > 0 else 0
    avg_word_host = sum(len(word) for word in hostname.split('.')) / len(hostname.split('.')) if hostname.split('.') else 0
    avg_word_path = sum(len(word) for word in path.split('/')) / len(path.split('/')) if path.split('/') else 0

    phish_hints = 1 if re.search(r"(login|signin|bank|account|update|secure|webscr)", url, re.IGNORECASE) else 0
    suspecious_tld = 1 if re.search(r"\.(zip|review|country|kim|cricket|science|work|party|gq|link|men|tk)", url) else 0
    domain = urlparse(url).netloc

    #Fetching additional information
    # try:
    #     whois_info = whois.whois(hostname)
    #     if whois_info:
    #         creation_date = whois_info.creation_date[0] if isinstance(whois_info.creation_date, list) else whois_info.creation_date
    #         if creation_date:
    #             domain_age = (datetime.now() - creation_date).days
    #         else:
    #             domain_age = 0

    #         dns_record = 1 if whois_info.name_servers else 0
    #         google_index = 1 if 'google' in whois_info.registrar.lower() else 0
    #         page_rank = 0  # Need an API or scraping method for this

    #         if whois_info.expiration_date:
    #             expiration_date = whois_info.expiration_date[0] if isinstance(whois_info.expiration_date, list) else whois_info.expiration_date
    #             if expiration_date:
    #                 domain_registration_length = (expiration_date - datetime.now()).days
    #             else:
    #                 domain_registration_length = 0
    #         else:
    #             domain_registration_length = 0
    #     else:
    #         domain_age = 0
    #         domain_registration_length = 0
    #         dns_record = 0
    #         google_index = 0
    #         page_rank = 0
    # except Exception as e:
    #     print("Error fetching whois info:", e)
    #     domain_age = 0
    #     domain_registration_length = 0
    #     dns_record = 0
    #     google_index = 0
    #     page_rank = 0
    # try:
    #   response = requests.get(url)
    # except:
    #   response = ""
    # iframe = Iframe(response)
    # mouseover = MouseOver(response)
    # rightclick = RightClick(response)
    # forwarding = Forwarding(response)

    features = {#'length_url':length_url,
                'length_hostname':length_hostname,
                'ip':ip,
                'nb_dots':nb_dots,
                'nb_hyphens':nb_hyphens,
                'nb_at':nb_at,
                'nb_qm':nb_qm,
                'nb_and':nb_and,
                'nb_eq':nb_eq,
                'nb_slash':nb_slash,
                'nb_semicolumn':nb_semicolumn,
                'nb_www':nb_www,
                'nb_com':nb_com,
                'https_token':https_token,
                'ratio_digits_url':ratio_digits_url,
                'ratio_digits_host':ratio_digits_host,
                'tld_in_subdomain':tld_in_subdomain,
                'abnormal_subdomain':abnormal_subdomain,
                'nb_subdomains':nb_subdomains,
                'prefix_suffix':prefix_suffix,
                'shortening_service':shortening_service,
                'length_words_raw':length_words_raw,
                'shortest_word_host':shortest_word_host,
                'longest_words_raw':longest_words_raw,
                'longest_word_host':longest_word_host,
                'longest_word_path':longest_word_path,
                'avg_words_raw':avg_words_raw,
                'avg_word_host':avg_word_host,
                'avg_word_path':avg_word_path,
                'phish_hints':phish_hints,
                'suspecious_tld':suspecious_tld,
                'trust':trust}
                # 'domain_registration_length':domain_registration_length,
                # 'domain_age':domain_age,
                # 'dns_record':dns_record,
                # 'google_index':google_index,
                # 'page_rank':page_rank}
                # 'iframe':iframe,
                # 'mouseover':mouseover,
                # 'rightclick':rightclick,
                # 'forwarding':forwarding}

    return pd.DataFrame([features])

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    url = request.form['url']
    features = extract_features(url)
    prediction = model.predict(features)
    result = 'Phishing' if prediction[0] == 1 else 'Legitimate'
    return render_template('index.html', prediction_text=f'The URL is {result}.')

if __name__ == '__main__':
    app.run(debug=True)
