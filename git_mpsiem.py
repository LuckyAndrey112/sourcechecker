import os
import pickle
import gitlab
import yaml
from loguru import logger

def get_clusters_from_gitlab_mpsiem():
    clusters_names = dict()
    logger.info(f'Connecting to Gitlab... {os.getenv("GITLAB_URL")}')
    gl = gitlab.Gitlab(url=os.getenv('GITLAB_URL'), private_token=os.getenv('GITLAB_TOKEN'), ssl_verify=False)
    project_id = 3091
    project = gl.projects.get(project_id)
    path = (f'templates/kustomize/monitoring/overlays/sbercloud/files/rules-clients/mpsiem-alerting-rule-generator/values/clients')
    files = [file for file in project.repository_tree(path=path, ref='main', recursive=True, all=True) if
                 file['type'] == 'blob']
    clusters = dict()
    for item in files:
        content = project.repository_raw_blob(item.get('id')).decode('utf-8')
        #print(content)
        data = yaml.safe_load(content)

        customer_name = data.get("customerSystem")
        for custom_alerts in data.get('logSourceType', []):

            if 'customSettings' in custom_alerts:
                for settings in custom_alerts['customSettings']:
                    if settings.get('type') == 'cluster':
                        clusters[customer_name] = [(settings.get('name'))]
        if len(clusters) > 0:
            clusters_names[item.get('name').split('.')[0]] = clusters
    logger.info('Writing mpsiem cluster names to file')
    with open('clusters_mpsiem.pkl', 'wb') as f:
        pickle.dump(clusters, f)
    #print(clusters)



