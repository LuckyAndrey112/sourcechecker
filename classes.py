import logging
import os
import re
import time
import requests
import json
import pickle
from os import getenv
from datetime import datetime, timezone, timedelta
from cryptography.fernet import Fernet
from flask.logging import default_handler
from requests.auth import HTTPBasicAuth
from requests.exceptions import HTTPError
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning, NotOpenSSLWarning

disable_warnings(category=InsecureRequestWarning)
disable_warnings(category=NotOpenSSLWarning)

logger = logging.getLogger(__name__)
logger.addHandler(default_handler)


class QradarChecker:
    url = None
    __session = requests.session()
    __token = None

    aql_search_uri = '/api/ariel/searches'

    def __init__(self, url, token):
        self.url = url
        self.__token = token

    def get_source_status(self, source: str):
        # query_filter = f"(name ilike '%{source}%')"
        query_filter = f"(name='{source}')"
        params = dict(filter=query_filter)
        check_url = f'/api/config/event_sources/log_source_management/log_sources'
        headers = dict(Range='items=0-100000', Version='15.1', Accept='application/json', SEC=self.__token)

        full_url = f'{self.url}{check_url}'
        try:
            res = self.__session.get(url=full_url, headers=headers, params=params, verify=False)
            res.raise_for_status()
            logger.info(f'Check source status in qradar - {source}')
            return res.json()
        except HTTPError:
            logger.error(f'Check source status failed in qradar. Source - {source}')
            raise HTTPError

    def get_source_last_time(self, source: str):
        try:
            data = self.get_source_status(source=source)
            if len(data) != 0 and int(data[0].get('last_event_time')) != 0:
                return (datetime.fromtimestamp(data[0].get('last_event_time') // 1000, tz=timezone.utc).
                        strftime('%d.%m.%Y %H:%M:%S %Z'))
        except:
            return None

    def check_source_enabled(self, source: str):
        try:
            data = self.get_source_status(source=source)
            if len(data) != 0 and data.get('enabled') is True:
                return True
        except:
            return False

    def create_aql_search(self, aql_query: str) -> str:
        params = dict(query_expression=aql_query)
        url = f'{self.url}{self.aql_search_uri}'
        headers = dict(Version='15.1', Accept='application/json', SEC=self.__token)
        res = self.__session.post(url=url, headers=headers, params=params, verify=False)
        res.raise_for_status()
        return res.json().get('search_id')

    def get_report_status(self, search_id: str) -> str:
        url = f'{self.url}/{self.aql_search_uri}/{search_id}'
        headers = dict(Version='15.1', Accept='application/json', SEC=self.__token)
        res = self.__session.post(url=url, headers=headers, verify=False)
        res.raise_for_status()
        return res.json().get('status')

    def get_report_results(self, search_id: str) -> dict:
        url = f'{self.url}/{self.aql_search_uri}/{search_id}/results'
        headers = dict(Version='15.1', Accept='application/json', SEC=self.__token)
        res = self.__session.get(url=url, headers=headers, verify=False)
        res.raise_for_status()
        return res.json()

    def check_status(self, search_status, search_id):
        if search_status == 'COMPLETED':
            print('Search Completed')
            return self.get_report_results(search_id=search_id)
        else:
            print('Waiting for 3 seconds...')
            time.sleep(3)
            status = self.get_report_status(search_id=search_id)
            return self.check_status(status, search_id)

    def get_sourcetype_statistics(self, aql: str):
        report_id = self.create_aql_search(aql_query=aql)

        report_data = self.check_status(search_status='WAIT', search_id=report_id).get('events')[0]
        report_data['EPS in Interval'] = int(report_data.get('EPS in Interval'))
        report_data['Number of Events in Interval'] = int(report_data.get('Number of Events in Interval'))
        return report_data

    def get_log_source_groups(self, source_filter):
        params = dict(fields='name, id', filter=source_filter)
        check_url = '/api/config/event_sources/log_source_management/log_source_groups'
        headers = dict(Range='items=0-100000', Version='15.1', Accept='application/json', SEC=self.__token)

        full_url = f'{self.url}{check_url}'
        try:
            res = self.__session.get(url=full_url, headers=headers, params=params, verify=False)
            res.raise_for_status()
            return res.json()
        except HTTPError:
            raise HTTPError

    def get_log_source_types(self):
        params = dict(fields='name, id', filter='internal=false')
        check_url = '/api/config/event_sources/log_source_management/log_source_types'
        headers = dict(Range='items=0-100000', Version='15.1', Accept='application/json', SEC=self.__token)

        full_url = f'{self.url}{check_url}'
        try:
            res = self.__session.get(url=full_url, headers=headers, params=params, verify=False)
            res.raise_for_status()
            return res.json()
        except HTTPError:
            raise HTTPError


class VMChecker:
    url = None
    auth = None
    session = requests.session()

    def __init__(self, url, username, password):
        self.url = url
        self.auth = HTTPBasicAuth(username=username, password=password)

    def alert_available(self, log_source_name: str):
        query = f'ALERTS{{job=~".*client-eps", alertstate="firing", log_source_name="{log_source_name}"}}'
        response = self.session.get(self.url + '/select/0/prometheus/api/v1/query',
                                    params={
                                        'query': query},
                                    auth=self.auth, verify=False)
        response.raise_for_status()
        response = response.json()
        logger.info(f'Check alerts available - {log_source_name}')
        if len(response.get('data').get('result')) == 0:
            return False
        else:
            return True

    def cluster_alert_available(self, cluster_name: str) -> bool:
        query = (f'ALERTS{{job=~".*client-eps", alertstate="firing", cluster_name="{cluster_name}"}}')
        response = self.session.get(self.url + '/select/0/prometheus/api/v1/query',
                                    params={
                                        'query': query},
                                    auth=self.auth, verify=False)
        response.raise_for_status()
        response = response.json()
        logger.info(f'Check cluster alerts available - {cluster_name}')
        if len(response.get('data').get('result')) == 0:
            return False
        else:
            return True

    def source_available(self, log_source_name: str):
        query = f'qradar_logsource_eps_critical{{job=~".*client-eps", log_source_name="{log_source_name}"}}'
        response = self.session.get(self.url + '/select/0/prometheus/api/v1/query',
                                    params={
                                        'query': query},
                                    auth=self.auth, verify=False)
        response.raise_for_status()
        response = response.json()
        logger.info(f'Check source available - {log_source_name}')
        if len(response.get('data').get('result')) != 0:
            return True
        else:
            return False


class VMCheckerMPSIEM:
    url = None
    auth = None
    session = requests.session()

    def __init__(self, customer_choice):
        self.vm_user = getenv("PROM_USERNAME")
        self.vm_password = getenv("PROM_PASSWORD")
        self.vm_url = getenv("PROM_URL")  #задавать без кавычек
        self.auth = HTTPBasicAuth(username=self.vm_user, password=self.vm_password)
        self.customer_choice = customer_choice.split("(")[0]

    def source_available(self, log_source_name: str):
        self.miliseconds_now = int(datetime.now().timestamp())
        self.miliseconds_minus1h = self.miliseconds_now - 3600000
        query = (f'mpsiem_source_eps_aggregated{{log_source_name="{log_source_name}"}}')
        response = self.session.get(self.vm_url + '/select/0/prometheus/api/v1/query',
                                    params={
                                        'query': query, 'start': f'{self.miliseconds_minus1h}',
                                        'end': f'{self.miliseconds_now}',
                                        'relative_time': 'last_5_minutes'},
                                    auth=self.auth, verify=False)
        response.raise_for_status()
        response = response.json()
        #print(self.miliseconds_minus1h,self.miliseconds_now)
        logger.debug(f'Check alerts available in VictoriaMetrics - {log_source_name}')
        if len(response.get('data').get('result')) == 0:
            logger.debug(f'No source available in VictoriaMetrics - {log_source_name}')
            return False
        else:
            logger.debug(f'Successful find source in VictoriaMetrics - {log_source_name}')
            return True

    def alert_available(self, log_source_name: str):
        self.miliseconds_now = int(datetime.now().timestamp())
        self.miliseconds_minus1h = self.miliseconds_now - 3600000
        query = f'ALERTS{{alertstate="firing", log_source_name="{log_source_name.split("(")[0]}"}}'
        response = self.session.get(self.vm_url + '/select/0/prometheus/api/v1/query',
                                    params={
                                        'query': query, 'start': f'{self.miliseconds_minus1h}',
                                        'end': f'{self.miliseconds_now}',
                                        'relative_time': 'last_60_minutes'},
                                    auth=self.auth, verify=False)
        response.raise_for_status()
        response = response.json()
        logger.debug(f'Check alerts available in VictoriaMetrics - {log_source_name}')
        if len(response.get('data').get('result')) == 0:
            logger.debug(f'No alerts available in VictoriaMetrics - {log_source_name}')
            return False
        else:
            logger.debug(f'Successful find alert in VictoriaMetrics - {log_source_name}')
            return True


    def request_mp_log_source_types(self):
        '''запрашивает через API VM данный о log sources MP всех заказчиков'''
        query = 'mpsiem_source_eps_aggregated'
        response = requests.get(self.vm_url + '/select/0/prometheus/api/v1/query',
                                        params={
                                            'query': query},
                                        auth=self.auth, verify=False)
        try:
            type_list=json.loads(response.text)["data"]["result"]
        except:
            type_list=[]

        log_source_list=[]
        for one_metric in type_list:
            try:
                log_source_list.append(one_metric["metric"]["log_source_type"])
            except:
                logger.error(f'Invalid log source in VictoriaMetrics - {one_metric}')
                continue
        log_source_list=list(set(log_source_list))
        return log_source_list

    def save_mp_log_source_types(self):
        '''сохраняет данные, полученные в методе выше в файл'''
        with open(f'coldcache/MPSIEM_types.json', 'w') as file:
            json.dump(self.request_mp_log_source_types(),file)
            #print(len(set(self.request_mp_log_source_types())))

    @staticmethod
    def get_mp_log_source_types():
        '''из файла получает список log sources'''
        try:
            with open('coldcache/MPSIEM_types.json', 'r') as f:
                result=f.read()[1:-1].replace("\"","").split(", ")
                #print(len(result), type(result), result)
                return result
        except:
            logger.warning('No log source found in MPSIEM_types.json file!')
            return []


    def update_mp_log_source_types(self):
        '''обновляет файл MPSIEM_types.json путем сложения множеств log sources'''
        old_list=self.get_mp_log_source_types()
        new_list=self.request_mp_log_source_types()
        old_set=set(old_list)
        new_set=set(new_list)
        update_list=list(old_set.union(new_set))
        logger.info(f'Updated log source types successfull. Old  count:'
                    f' {len(old_set)}, New count: {len(new_set)} Result: {len(update_list)}')
        #print(len(old_list))
        #print("old", old_set)
        #print("new", new_set)
        #print(len(new_set))
        #print(len(update_list))
        with open(f'coldcache/MPSIEM_types.json', 'w') as file:
            json.dump(update_list, file)

    @staticmethod
    def vendor_title_split(string):
        '''Подается на вход microsoft|windows или просто unix-like, метод разделяет на vendor и title'''
        vendor=''
        title=''
        split=string.split('|')
        if len(split)>1:
            vendor=split[0]
            title=split[1]
            return vendor,title
        elif len(split)==1:
            title=string
            return (title,)

    def request_mp_cluster(self):
        '''запрашивает через API VM данные о кластерах MP всех заказчиков'''
        query = 'mpsiem_source_eps_aggregated{service="MP_SIEM"}'
        response = requests.get(self.vm_url + '/select/0/prometheus/api/v1/query',
                                        params={
                                            'query': query},
                                        auth=self.auth, verify=False)
        try:
            type_list=json.loads(response.text)["data"]["result"]
        except:
            type_list=[]
        customers_list=[]
        log_source_dict={}
        for one_metric in type_list:
            try:
                customers_list.append(one_metric["metric"]["infosystem"].replace("-INFRA",""))
            except:
                logger.error("Error in customers list key")
                continue
        customers_list=list(set(customers_list))
        for customer in customers_list:
            log_source_list = []
            for one_metric in type_list:
                try:
                    if one_metric["metric"]["infosystem"].replace("-INFRA","") == customer:
                        log_source_list.append(one_metric["metric"]["installation"])
                except:
                    logger.error(f'Invalid get clusters in VictoriaMetrics - {one_metric}')
                    continue
            log_source_list = list(set(log_source_list))
            log_source_dict[customer]=log_source_list
            logger.info('Clusters request successfully received')
        return log_source_dict


    def save_mp_cluster(self):
        "сохраняет данные из метрода выше в файл"
        result=self.request_mp_cluster()
        with open(f'coldcache/MPSIEM_clusters.json', 'w') as file:
            json.dump(result,file)
            logger.info('Clusters data successfully saved')

    @staticmethod
    def get_mp_cluster():
        '''из файла получает список кластеров'''
        try:
            with open('coldcache/MPSIEM_clusters.json', 'r') as file:
                result=json.load(file)
                return result
        except:
            logger.warning('No clusters found in MPSIEM_types.json file!')
            return []


    def mp_cluster_alert_available(self, infosystem:str) -> bool:
        "проверяет наличие алерта по заданному кластеру MP SIEM"
        query = (f'ALERTS{{service="MP_SIEM", alertstate="firing", installation="{infosystem}"}}')
        response = self.session.get(self.vm_url + '/select/0/prometheus/api/v1/query',
                                    params={
                                        'query': query},
                                    auth=self.auth, verify=False)
        response.raise_for_status()
        response = response.json()
        logger.info(f'Check cluster alerts available - {infosystem}')
        if len(response.get('data').get('result')) == 0:
            return False
        else:
            return True


class CryptoPassMP:
    def __init__(self, cryptokey):
        self.key = cryptokey
        self.fernet = Fernet(self.key)

    def encrypt_file(self, file):
        '''используется для добавления заказчиков в файл и последующего шифрования, в скрипте не используется'''
        self.file = file
        with open(self.file, 'rb') as file:
            original = file.read()
        encrypted = self.fernet.encrypt(original)
        return encrypted

    def encrypt_json(self, original):
        '''шифрует несериализованный json, т е original - список со вложенными словарями'''
        encrypted = self.fernet.encrypt(original)
        return encrypted

    def decrypt(self, filedecrypt):
        '''decrypt, можно использовать json.loads к результату функции'''
        self.filedecrypt = filedecrypt
        with open(self.filedecrypt, 'rb') as enc_file:
            encrypted = enc_file.read()
        decrypted = self.fernet.decrypt(encrypted)
        return decrypted

    def save(self, file_save, data_write):
        '''сохраняет креды data_write в файл file_save в зашифрованном виде'''
        self.file_save_encrypt = file_save
        with open(self.file_save_encrypt, "wb") as file:
            file.write(bytes(data_write))

    def get_names(self, file):
        '''позволяет получить имена заказчиков для выпадающего списка web-интерфейса'''
        self.file = file
        js = json.loads(self.decrypt(self.file).decode('utf-8').replace("'", "\""))
        result = []
        for i in js:
            result.append(i['customer_name'])
        return result

    @staticmethod
    def decrypt_secret():
        '''дешифрует файл secret.json, в основном коде не используется'''
        cryptopass = CryptoPassMP(getenv('SECRET_KEY_MP'))
        b = cryptopass.decrypt('secret.json')
        cryptopass.save('secret.json', b)

    @staticmethod
    def encrypt_secret():
        '''шифрует файл secret.json, в основном коде не используется'''
        cryptopass = CryptoPassMP(getenv('SECRET_KEY_MP'))
        a = cryptopass.encrypt_file('secret.json')
        cryptopass.save('secret.json', a)


class SecretCreds:
    def __init__(self, file):
        self.file = file
        self.key = getenv('SECRET_KEY_MP')
        self.cryptopass = CryptoPassMP(self.key)
        self.decrypt_file = self.cryptopass.decrypt(self.file)
        '''для корректной сериализации json нужны двойные кавычки'''
        self.response = json.loads(self.decrypt_file.decode('utf-8').replace("'", "\""))

    def get_enviroment(self, customer_name: str) -> tuple:
        '''получает креды для подключения для выбранного заказчика'''
        for i in self.response:
            if i["customer_name"].split("(")[0] == customer_name or i["customer_name"] == customer_name:
                self.__url = i["data"]["url"]
                self.__user = i["data"]["user"]
                self.__password = i["data"]["password"]
                self.__token = i["data"]["token"]
                self.__secret_key = i["data"]["client_secret"]
                self.number = i["data"]["number"]

        return self.__url, self.__user, self.__password, self.__secret_key, self.__token, self.number

    def set_token(self, token: str, customer_name: str) -> None:
        '''позволяет перезаписать токен в зашифрованном файле'''
        for i in self.response:
            if i["customer_name"] == customer_name:
                number = i["data"]["number"]

        self.response[number]['data']['token'] = token
        set_encrypted = self.cryptopass.encrypt_json(bytes(str(self.response), 'utf-8'))
        self.cryptopass.save(self.file, set_encrypted)


class GetTokenMP:
    '''Класс проверяет, корректен ли существующи токен,
    и при необходимости автоматически запрашивает новый'''

    def __init__(self, customer_choice):
        self.secret_creds = SecretCreds('secret.json')
        self.customer_choice = customer_choice
        secret_env = self.secret_creds.get_enviroment(self.customer_choice)
        self.__mpsiem_url = secret_env[0]
        self.__mpsiem_user = secret_env[1]
        self.__mpsiem_password = secret_env[2]
        self.__mpsiem_client_secret = secret_env[3]
        self.__mpsiem_token = secret_env[4]
        if self.__mpsiem_url is None:
            self.__mpsiem_url = "None"
            logger.warning('Environment variable MP_URL is not set')
        self.__url = self.__mpsiem_url + ':3334/connect/token'
        self.headers = {
            'content-type': 'application/x-www-form-urlencoded',
        }

        self.data = {
            'username': self.__mpsiem_user,
            'password': self.__mpsiem_password,
            'client_id': 'mpx',
            'client_secret': self.__mpsiem_client_secret,
            'grant_type': 'password',
            'response_type': 'id_token',
            'scope': 'mpx.api'
        }

    def testconnection(self):
        '''Метод производит тестовый запрос под существующим токеном
        Если код ответа 200, он возвращет True, иначе - False'''
        #self.__mpsiem_token=self.secret_creds.get_enviroment(customer_choice)[4]
        self.headerstest = {"Authorization": f"Bearer {self.__mpsiem_token}"}
        try:
            response = requests.get(f'{self.__mpsiem_url}/api/scopes/v2/scopes', headers=self.headerstest,
                                    timeout=7, verify=False)
            logger.info(f'Successful Test connection. Status Code {response.status_code}')
        except:
            logger.error(f'Error of HTTP request of resourse {self.__url} {response.status_code}')

        self.codetest = response.status_code
        if self.codetest == 200:
            logger.info('MP SIEM API token is valid. Success')
            return True
        else:
            logger.warning('MP SIEM API token is invalid or expired. Try to request new token')
            return False

    def __call__(self):
        '''При вызове класса запрашивается новый токен, если существующий устарел или не существует'''
        tokeniscorrect = self.testconnection()
        if tokeniscorrect:
            return self.__mpsiem_token
        else:
            response = requests.post(self.__url, data=self.data, headers=self.headers, verify=False)
            logger.error(f'Error of HTTP request of resourse {self.__url}')
            try:
                self.__mpsiem_token = response.json()['access_token']
                self.secret_creds.set_token(self.__mpsiem_token, self.customer_choice)
                logger.info("New token successfully received")
            except:
                logger.error(f'Error of received MP SIEM token')
            return self.__mpsiem_token

    @property
    def mpvm_token(self):
        return self.__mpsiem_token

    @property
    def mpvm_url(self):
        return self.__mpsiem_url


class HostClassMP:
    '''Класс отвечает за храние данных каждого запроса MPSIEM вида title|vendor @ 127.0.0.1[Customer]
    Ниже в коде из строки будут извлечены данные и добавлены свойства status,last_seen_time'''

    def __init__(self, name):
        self.name = name
        self.status = "Не задано"


class GetLastTimeMP:
    '''Класс отвечает за получение целевых данных: статуса алерта из VM, времени последнего события MP'''

    def __init__(self, customer_choice: str):
        '''customer_choice - строка, содержащая имя заказчика, должна совпадать с именем заказчика в secret.json'''
        gettoken = GetTokenMP(customer_choice)
        gettoken()
        self.client = customer_choice
        self.mpvm_token = gettoken.mpvm_token
        self.mpvm_url = gettoken.mpvm_url
        self.headers = {"Authorization": f"Bearer {self.mpvm_token}"}
        self.last_time_array = []
        self.response_js = {}
        self.host_spisok = []

    #############

    @staticmethod
    def split_space(stringg):
        try:
            array = [stringg.split(" ")[0], stringg.split(" ")[1][1:-1]]
        except:
            array = ["", ""]
        return array

    def any_request(self,request:str,method,params=''):
        session = requests.session()
        self.url = f'{self.mpvm_url}/{request}'
        if method == 'GET':
            response = session.get(self.url, headers=self.headers, verify=False)
        elif method == 'POST':

            try:
                json_params = json.loads(params)
                response = session.post(self.url, headers=self.headers, verify=False, json=json_params)
                return json.loads(response.text)
            except:
                json.loads({})

    def hostname_split(self, request: str) -> HostClassMP:
        '''Парсит данные запроса вида title|vendor @ 127.0.0.1[Customer]
        и добавляет их в виде свойств класса HostClassMP'''
        hostclass = HostClassMP(request)
        try:
            hostclass.hostname = request.split(" @ ")[1].split("[")[0]
            hostclass.bizone_client = f'{request.split(" @ ")[1].split("[")[1][:-1]}'
            hostclass.channel = request.split(" @ ")[0]

            if "|" not in hostclass.channel:
                hostclass.title = hostclass.channel
                hostclass.vendor = hostclass.channel
            else:
                hostclass.vendor = hostclass.channel.split("|")[0]
                hostclass.title = hostclass.channel.split("|")[1]

        except IndexError:
            logger.error(f"Invalid request format \"{request}\"")
            hostclass.vendor = None
            hostclass.title = None
            hostclass.channel = None
            hostclass.hostname = None
            hostclass.bizone_client = None
        logger.debug(f'Requset \"{request}\" is correct. Success')

        return hostclass

    def lasttime_from_events(self,host,vendor,title,delta_time):
        miliseconds_now = int(datetime.now().timestamp())
        miliseconds_delta = miliseconds_now - (3600*delta_time)
        self.post_url=f'{self.mpvm_url}/api/events/v3/events/'
        #self.post_headers={'Authorization': f'Bearer {self.mpvm_token}'}
        if vendor != title:
            pdql_filter=(f'event_src.host = \"{host}\" and event_src.vendor=\"{vendor}\" and event_src.title=\"{title}\"')
        else:
            pdql_filter=(f'event_src.host = \"{host}\" and event_src.vendor=\"{vendor}\"')

        post_payload = {
            "filter": f'filter({pdql_filter}) | select(time,event_src.hostname) | sort(time desc)',
            "groupValues": [],
            "timeFrom": miliseconds_delta,
            "timeTo": None
        }
        params={
            'offset':0,
            'limit':1
        }

        response=requests.post(self.post_url,json=post_payload, params=params, headers=self.headers,verify=False)
        js=json.loads(response.text)["events"]
        try:
            last_time=f'{(datetime.strptime(js[0]["time"][:-9], '%Y-%m-%dT%H:%M:%S')).strftime(
                "%d-%m-%Y %H:%M:%S")} UTC'
        except IndexError:
            last_time=None
            if vendor==title:
                pdql_filter = (f'event_src.host = \"{host}\" and event_src.title=\"{title}\"')
                post_payload = {
                    "filter": f'filter({pdql_filter}) | select(time) | sort(time desc)',
                    "groupValues": [],
                    "timeFrom": miliseconds_delta,
                    "timeTo": None
                    }
                response = requests.post(self.post_url, json=post_payload, params=params, headers=self.headers, verify=False)
                js = json.loads(response.text)["events"]
                try:
                    last_time = f'{(datetime.strptime(js[0]["time"][:-9], '%Y-%m-%dT%H:%M:%S')).strftime(
                "%d-%m-%Y %H:%M:%S")} UTC'
                except IndexError:
                    last_time=None
        return last_time


    def __call__(self, hostname_array: list):

        '''обращается по API к MP SIEM и VictoriaMetrics, и формирует список с итоговыми данными'''
        '''1-ая часть. метод находит последнее событие за последний час, если такое имеется'''

        for hostname in hostname_array:
            '''1-ая часть - легкий запрос за 1 час'''
            host_class = self.hostname_split(hostname)
            self.host_spisok.append(host_class)
            hostname = host_class.hostname
            vendor = host_class.vendor
            title = host_class.title
            last_time = self.lasttime_from_events(hostname,vendor,title,1)

            if hostname == None and vendor == None and title == None:
                host_class.status = 'Некорректный запрос'
                host_class.lastSeenTime = 'Время отсутствует'

                logger.warning('Not found, because request incorrect')
                continue

            elif host_class.bizone_client != self.client.split("(")[0]:
                host_class.status = 'Неверно выбран заказчик'
                host_class.lastSeenTime = 'Время отсутствует'
                logger.warning('Not found, because customer incorrect')
                continue

            vmchecker = VMCheckerMPSIEM(self.client)
            '''проверка доступности события и алерта в VictoriaMetrics'''
            alert_available = vmchecker.alert_available(host_class.name)
            source_available = vmchecker.source_available(host_class.name)
            if alert_available:
                host_class.status = "Найден алерт"
            else:
                host_class.status = "ОК"
                if not source_available:
                    host_class.status = "Источник не найден в prometheus"
                    host_class.lastSeenTime = 'Время отсутствует'

            last_time  = self.lasttime_from_events(hostname,vendor,title,1)
            if last_time != "Время отсутствует" and last_time != None:
                logger.debug(f'Success try to get hot cache from {hostname}')
                host_class.lastSeenTime = last_time
                continue


            '''2-я часть - если время не найдено легким запросом, производит более тяжелый запрос, за неделю'''
            if last_time == 'Время отсутствует' or last_time == None:
                cache_last_time = self.lasttime_from_events(hostname,vendor,title,144)
                logger.info('Received information about events for 7 days')
                if cache_last_time != None:
                    if cache_last_time == "Время отсутствует":
                        host_class.lastSeenTime = "События отсутствуют более 7 дней"
                    else:
                        host_class.lastSeenTime = f'{cache_last_time}'
                        host_class.status = 'Последнее событие более 1 часа назад'
                else:
                    logger.info(f'cache {hostname} not found')
                    host_class.lastSeenTime = 'Время cобытий отсутствует за последние 7 дней'
                    host_class.status = "События отсутствуют более 7 дней"


class MPSourceChecker:
    def __init__(self, log_source_name_array):
        self.log_source_name_array = log_source_name_array

    @staticmethod
    def validate_request_one(string):
        pattern = r'\S+.@.\S+[\S+].+?'
        match = re.search(pattern, string, re.IGNORECASE)
        if match:
            #print(match)
            if match[0] == string:
                return True
        return False

    @staticmethod
    def validate_request_all(hostname_list:list):
        validate=any(map(lambda host:MPSourceChecker.validate_request_one(host), hostname_list))
        return validate

    def __call__(self, customer_choice: str) -> dict:
        '''подготавливает данные c результатами для формы Flask в виде словаря'''
        self.result = []
        if not self.validate_request_all(self.log_source_name_array):
            logger.error('All requests not correct, check requsets format aaa|bbb @ [client_name]')
            return []
        else:
            getlasttime = GetLastTimeMP(customer_choice)
            self.last_time_event = getlasttime(self.log_source_name_array)
            keys = ['name', 'status', 'last_time_event']
            for host in getlasttime.host_spisok:
                values = tuple([host.name, host.status, host.lastSeenTime])
                result_dict = {k: v for k, v in zip(keys, values)}
                self.result.append(result_dict)
            return self.result


#s='microsoft|windows @ dhcp03.inner.alfaleasing.ru[ALFAMOB]'
#s='unix_like @ cpmgmt[ALFAMOB]'
#s='1c|1c_enterprise @ 10.41.8.70[RAMBLER]'
#GetLastTimeMP("ALFAMOB").lasttime_from_events('dhcp03.inner.alfaleasing.ru','microsoft','windows',1)

#hosts=[HostClassMP('1c|1c_enterprise @ 10.41.8.70[RAMBLER]')]
#hosts=['1c|1c_enterprise @ 10.41.8.70[ALFAMOB]','unix_like @ cpmgmt[ALFAMOB]','microsoft|windows @ dhcp03.inner.alfaleasing.ru[ALFAMOB]']
#hosts=['microsoft|windows @ dhcp03.inner.alfaleasing.ru[ALFAMOB]']
#times=GetLastTimeMP("ALFAMOB")(hosts)
#print(times)