import json
import os
import pickle
from datetime import datetime, timezone, timedelta

from flask import Flask, render_template, request
from flask_apscheduler.scheduler import BackgroundScheduler
from flask_bootstrap import Bootstrap5
from flask_wtf import CSRFProtect
from loguru import logger

from classes import QradarChecker, VMChecker,GetLastTimeMP,CryptoPassMP,MPSourceChecker,VMCheckerMPSIEM
from git import get_clusters_from_gitlab
from git_mpsiem import get_clusters_from_gitlab_mpsiem
from groups_mappings import QRADAR_GROUPS
from ui.forms import CheckerInterface, SourceTypes, SourceTypesMP, ClusterForm,MPCheckerInterface
from flask_apscheduler import APScheduler

from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

from os import getenv
disable_warnings(category=InsecureRequestWarning)

app = Flask(__name__)
bs = Bootstrap5(app)
csrf = CSRFProtect(app)
scheduler = BackgroundScheduler()

env_config = os.getenv('APP_SETTINGS', 'config.ProductionConfig')
app.config.from_object(env_config)
app.static_folder = 'static'
app.jinja_env.autoescape = True

prom_checker = VMChecker(url=app.config.get('PROM_URL'), username=app.config.get('PROM_USERNAME'),
                         password=app.config.get('PROM_PASSWORD'))
qradar = QradarChecker(url=app.config.get('QRADAR_HOST'), token=os.getenv('SEC_TOKEN', ''))
qradar_ttc = QradarChecker(url=app.config.get('TTC_QRADAR_HOST'), token=os.getenv('TTC_SEC_TOKEN', ''))

scheduler.add_job(func=get_clusters_from_gitlab,
                  trigger='interval', seconds=60,
                  id='get_clusters_from_gitlab',
                  name='get_clusters_from_gitlab',
                  replace_existing=True)

scheduler.add_job(func=get_clusters_from_gitlab_mpsiem,
                  trigger='interval', seconds=600,
                  id='get_clusters_from_gitlab_mpsiem',
                  name='get_clusters_from_gitlab_mpsiem',
                  replace_existing=True)

#scheduler.add_job(func=print_date_time, trigger='interval', id='print_date_time', seconds=30)

scheduler.start()

mpscheduler_cache = APScheduler()

@mpscheduler_cache.task("interval", id="cron_mp_log_sources", seconds=43200, max_instances=1)
def job_log_sources():
    cl = VMCheckerMPSIEM('')
    cl.update_mp_log_source_types()
    logger.info('MPSIEM log sources types job completed')

@mpscheduler_cache.task("interval", id="mp_clusters",seconds=43200, max_instances=1)
def job_mp_clusters():
    cl=VMCheckerMPSIEM('')
    cl.save_mp_cluster()
    logger.info('MPSIEM cluster job completed')

mpscheduler_cache.api_enabled = True
mpscheduler_cache.init_app(app)
'''незамедлительный запуск шедулера'''
try:
    mpscheduler_cache.run_job("cron_mp_log_sources")
    mpscheduler_cache.start()
    #mpscheduler_cache.run_job("mp_clusters")
    #mpscheduler_cache.start()
    logger.info('scheduler started')
except:
    logger.info('cache error')

@app.route('/', methods=['GET', 'POST'])
def index():
    checker_form = CheckerInterface()
    source_dict = {}
    radar_dict = {}
    if checker_form.validate_on_submit() and request.method == 'POST':
        sources = set(request.form.get('sources').splitlines())
        check_all = request.form.get('check_all')
        console = request.form.get('qradar_host')

        for source in sources:
            if console == 'bz':
                qradar_time = qradar.get_source_last_time(source=source)
                source_available = qradar.get_source_status(source=source)
                source_enabled = qradar.check_source_enabled(source=source)
            else:
                qradar_time = qradar_ttc.get_source_last_time(source=source)
                source_available = qradar_ttc.get_source_status(source=source)
                source_enabled = qradar_ttc.check_source_enabled(source=source)
            try:
                if qradar_time is not None:
                    qradar_date_object = (datetime.strptime(qradar_time, '%d.%m.%Y %H:%M:%S %Z').
                                          replace(tzinfo=timezone.utc))
                    lag = (datetime.now(tz=timezone.utc) - qradar_date_object).days
                else:
                    lag = 0
            except ValueError:
                logger.error(f'[BUG] Source check - {source}')
                logger.error(qradar_time)
                continue

            if source_enabled:
                source_dict[source] = 'Источник отключен в SIEM'

            alert_available = prom_checker.alert_available(log_source_name=source)
            prom_source_available = prom_checker.source_available(log_source_name=source)
            if alert_available and prom_source_available:
                source_dict[source] = 'Найден алерт'
                if qradar_time is not None:
                    radar_dict[source] = qradar_time
                else:
                    radar_dict[source] = 'Время отсутствует'
            elif not prom_source_available:
                source_dict[source] = 'Источник не найден в prometheus'
                if qradar_time is not None:
                    radar_dict[source] = qradar_time
                else:
                    radar_dict[source] = 'Время отсутствует'
            elif lag > 8:
                source_dict[source] = 'Отсутствие событий более 8 дней'
                radar_dict[source] = qradar_time
            else:
                if check_all:
                    source_dict[source] = 'ОК'
                    if console == 'bz':
                        radar_dict[source] = qradar_time
                    else:
                        radar_dict[source] = qradar_time
            if len(source_available) == 0:
                source_dict[source] = 'Источник не найден в SIEM'

        return render_template('base.html', title='Проверка источника', form=checker_form,
                               sources=source_dict, qradar_sources=radar_dict)
    else:
        return render_template('base.html', title='Проверка источника', form=checker_form)


@app.route('/source_types', methods=['GET', 'POST'])
def source_types():
    types_form = SourceTypes()
    types_choices = qradar.get_log_source_types()
    sorted_types_choices = sorted(types_choices, key=lambda k: k.get('name', 0), reverse=False)
    types_form.source_types.choices = [(item.get('id'), item.get('name')) for item in sorted_types_choices]

    infrasystems_choices = qradar.get_log_source_groups(
        source_filter='(owner="1d22ef17-c034-4278-b43e-c967c2b0dc74" or owner="5ce3db82-5b11-4b75-b80a-25965c851844") '
                      'and parent_id=100126')

    sorted_infrasystems_choices = sorted(infrasystems_choices, key=lambda k: k.get('name', 0), reverse=False)
    types_form.domain.choices = [(item.get('id'), item.get('name')) for item in sorted_infrasystems_choices]

    if types_form.validate_on_submit() and request.method == 'POST':
        source_type = None
        domain = None

        for _ in types_choices:
            if _.get('id') == int(request.form.get('source_types')):
                source_type = _.get('name')

        for _ in infrasystems_choices:
            if _.get('id') == int(request.form.get('domain')):
                domain = _.get('name')
        check_time = int(request.form.get('check_time'))

        # Обогащение домена, перевод из нового стиля в старый
        if domain in QRADAR_GROUPS:
            domain = QRADAR_GROUPS.get(domain)
        else:
            domain = domain.replace("-INFRA", "")
        try:
            query = (f"SELECT LOGSOURCETYPENAME(devicetype) AS 'LogSourceType', "  # noqa
                     f"devicetype, "
                     f"domainid, "
                     f"SUM(eventcount) AS 'Number of Events in Interval', "
                     f"SUM(eventcount)/{check_time * 60} AS 'EPS in Interval', "
                     f"domain_name "
                     f"FROM events WHERE domain_name ILIKE '%{domain}%' "
                     f"AND LogSourceType = '{source_type}' "
                     f"LAST {check_time} MINUTES")

            data = qradar.get_sourcetype_statistics(aql=query)
            if data.get('EPS in Interval') != 0 and \
                    data.get('Number of Events in Interval') != 0:
                data['status'] = 'OK'
            else:
                data['status'] = 'Мало событий'
        except:
            data = {'EPS in Interval': 0, 'FIRST_domain_name': domain, 'LogSourceType': source_type,
                    'Number of Events in Interval': 0, 'status': 'События не найдены'}

        return render_template('base.html', title='Проверка типов источников', form=types_form,
                               source_type_data=data, check_time=check_time)
    else:
        return render_template('base.html', title='Проверка типов источников', form=types_form)



@app.route('/cluster', methods=['GET', 'POST'])
def cluster():
    cluster_form = ClusterForm()
    cluster_dict = {}

    with open('clusters.pkl', 'rb') as f:
        cluster_names = pickle.load(f)

    cluster_form.cluster_name.choices = cluster_names

    if cluster_form.validate_on_submit() and request.method == 'POST':
        cl_name = None

        for key, val in cluster_names.items():
            cluster_id_dict={}
            for id in val:
                cluster_id_dict[id[0]]=id[1]
            if request.form.get('cluster_name') in cluster_id_dict.keys():
                cl_name = cluster_id_dict[request.form.get('cluster_name')]

        if prom_checker.cluster_alert_available(cluster_name=cl_name):
            cluster_dict[cl_name] = 'Найден алерт'
        else:
            cluster_dict[cl_name] = 'ОК'

        return render_template('base.html', title='Проверка кластера', form=cluster_form,
                               cluster_data=cluster_dict)
    else:
        return render_template('base.html', title='Проверка кластера', form=cluster_form)


@app.route('/mpsiem', methods=['GET', 'POST'])
def mpsiem_checker():
    key=getenv("SECRET_KEY_MP")
    customers=CryptoPassMP(key).get_names('secret.json')
    mp_form = MPCheckerInterface()
    mp_form.customer.choices = customers

    if mp_form.validate_on_submit() and request.method == 'POST':
        mp_sources = set(request.form.get('sources').splitlines())
        check_all = request.form.get('check_all')
        global customer_choice
        customer_choice=request.form.get('customer')
        #mp_data=[{'name': '123', 'status': 'ОК', 'date': 'Not Found'},{'name': '12345', 'status': 'Ne ОК', 'date': 'Not Found'}]
        mp_data=MPSourceChecker(list(mp_sources))(customer_choice)
        if check_all:
            pass
        else:
            mp_data = list(filter(lambda x: x["status"] != "ОК" and x["status"] != 'Некорректный запрос', mp_data))

        return render_template('base.html', title='MPSIEM', form=mp_form, mp_data=mp_data)
    else:
        return render_template('base.html', title='MPSIEM', form=mp_form)


@app.route('/mpsiem_source_types', methods=['GET', 'POST'])
def mpsiem_source_types():
    key = getenv("SECRET_KEY_MP")
    customers = CryptoPassMP(key).get_names('secret.json')
    types_form = SourceTypesMP()
    types_form.source_types.choices = sorted(VMCheckerMPSIEM.get_mp_log_source_types())
    infrasystems_choices = [{"name": i} for i in customers]
    sorted_infrasystems_choices = sorted(infrasystems_choices, key=lambda k: k.get('name', 0), reverse=False)
    types_form.domain.choices = [(item.get('name')) for item in sorted_infrasystems_choices]

    if types_form.validate_on_submit() and request.method == 'POST':
        source_type = None
        domain = None

        vendor_title = VMCheckerMPSIEM.vendor_title_split(request.form.get('source_types'))
        check_time = int(request.form.get('check_time'))
        source_type = request.form.get('source_types')
        domain = request.form.get('domain')
        MP = GetLastTimeMP(domain)
        timedeltaminutes = int((datetime.now() - timedelta(minutes=int(request.form.get('check_time')))).timestamp())
        if len(vendor_title) ==2 :
            resp = MP.any_request('api/events/v3/events/aggregation', "POST",
                              '{\"filter\":\"filter(((event_src.vendor = \\"'
                              f'{vendor_title[0]}'
                              '\\")) AND (event_src.title = \\"'
                              f'{vendor_title[1]}'
                              '\\"))'
                              ' | select(time) | sort(time desc) | group(key: [event_src.title, event_src.vendor], agg: COUNT(*) as Cnt) '
                              f'| sort(Cnt desc) | limit(10000)\",\"timeFrom\":{timedeltaminutes}'
                              '}')
        elif len(vendor_title) == 1:
            resp = MP.any_request('api/events/v3/events/aggregation', "POST",
                                  '{\"filter\":\"filter(((event_src.vendor = \\"'
                                  f'{vendor_title[0]}'
                                  '\\")) OR (event_src.title = \\"'
                                  f'{vendor_title[0]}'
                                  '\\"))'
                                  ' | select(time) | sort(time desc) | group(key: [event_src.title, event_src.vendor], agg: COUNT(*) as Cnt) '
                                  f'| sort(Cnt desc) | limit(10000)\",\"timeFrom\":{timedeltaminutes}'
                                  '}')
        try:
            events_count=resp['rows'][0]['values'][0]
        except:
            events_count=0
        eps=round((events_count/(60*check_time)),2)
        if eps > 0:
            status = 'OK'
        elif eps==0 and events_count > 0:
            status = 'Мало событий'
        elif eps==0 and events_count==0:
            status = 'События отсутствуют'

        data = {'EPS in Interval': eps, 'FIRST_domain_name': domain, 'LogSourceType': source_type,
                    'Number of Events in Interval': int(events_count), 'status': status}

        return render_template('base.html', title='Проверка типов источников', form=types_form,
                               source_type_data=data, check_time=check_time)

    else:
        return render_template('base.html', title='Проверка типов источников', form=types_form)


@app.route('/cluster_mpsiem', methods=['GET', 'POST'])
def cluster_mpsiem():
    cluster_form = ClusterForm()
    cluster_dict = {}
    with open('clusters_mpsiem.pkl', 'rb') as f:
        cluster_names = pickle.load(f)
    cluster_form.cluster_name.choices=cluster_names
    if cluster_form.validate_on_submit() and request.method == 'POST':
        cl_name = request.form.get('cluster_name')
        for customer in cluster_names.keys():
            if cl_name in cluster_names[customer]:
                customer_name=customer
        VMcheck=VMCheckerMPSIEM("")
        if VMcheck.mp_cluster_alert_available(cl_name):
            cluster_dict["status"] = 'Найден алерт'
        else:
            cluster_dict["status"] = 'ОК'
        cluster_dict["infosystem"] = cl_name
        cluster_dict["customer"] = customer_name

        return render_template('base.html', title='Проверка кластера', form=cluster_form,
                               mp_cluster_data=cluster_dict)
    else:
        return render_template('base.html', title='Проверка кластера', form=cluster_form)

if __name__ == '__main__':
    #app.debug = True
    #app.run(use_reloader=False)
    app.run(host='0.0.0.0', port=8000, debug=False,use_reloader=False)