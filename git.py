import json
import os
import pickle
from datetime import datetime
from pprint import pprint
from uuid import uuid4

import gitlab
import yaml
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning, NotOpenSSLWarning

from loguru import logger

disable_warnings(category=InsecureRequestWarning)
disable_warnings(category=NotOpenSSLWarning)


# @scheduler.task('cron', id='gitlab_sync', minute='1', hour='*', day_of_week='')
def get_clusters_from_gitlab():
    clusters_names = dict()
    logger.info(f'Connecting to Gitlab... {os.getenv("GITLAB_URL")}')
    gl = gitlab.Gitlab(url=os.getenv('GITLAB_URL'), private_token=os.getenv('GITLAB_TOKEN'), ssl_verify=False)
    project_id = 3091
    project = gl.projects.get(project_id)
    path = (f'templates/kustomize/monitoring/overlays/sbercloud/'
            f'files/rules-clients/qradar-alerting-rule-generator/values/clients')
    # Удаление директорий
    files = [file for file in project.repository_tree(path=path, ref='main', recursive=True, all=True) if
             file['type'] == 'blob']
    logger.info(f'Found {len(files)} files')
    for item in files:
        content = project.repository_raw_blob(item.get('id')).decode('utf-8')
        data = yaml.safe_load(content)
        clusters = list()
        for custom_alerts in data.get('logSourceType',[]):
            if 'customSettings' in custom_alerts:
                for settings in custom_alerts['customSettings']:
                    if settings.get('type') == 'cluster':
                        clusters.append((str(uuid4()), settings.get('name')))
        if len(clusters) > 0:
            clusters_names[item.get('name').split('.')[0]] = clusters
    logger.info('Writing cluster names to file')
    print(clusters_names)
    with open('clusters.pkl', 'wb') as f:
        pickle.dump(clusters_names, f)


def print_date_time():
    print(datetime.now())
