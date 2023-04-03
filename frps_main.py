#!/usr/bin/btpython
# coding: utf-8

# 本插件外部引用地址列表

# https://ip.iw3c.top
# 获取当前服务器的外网ip地址信息,用于签发 TLS 加密证书

# https://cdn.iw3c.com.cn/bt-plugin/frp/data.json
# 获取当前CDN 服务器上云端存放的可供切换的frp 版本信息的json


import os,sys,base64,json,time,uuid,re
import psutil,requests

os.chdir("/www/server/panel")
sys.path.append("class/")
import public, db, firewalls, panelTask

# 插件安装目录
plugin_path = "/www/server/panel/plugin/frps/"
# 插件数据库文件地址 , 相对宝塔默认 data 地址
db_path =  '../plugin/frps/data/frps'
# 需要检查是否存在端口冲突的配置参数
configs_checkport = ['bind_port', 'bind_udp_port', 'kcp_bind_port', 'dashboard_port', 'vhost_http_port',
                     'vhost_https_port', 'tcpmux_httpconnect_port']
# 需要自动放行防火墙的配置参数
configs_firewall = ['bind_port', 'bind_udp_port', 'kcp_bind_port', 'allow_ports', 'vhost_http_port', 'vhost_https_port',
                    'tcpmux_httpconnect_port']
# 默认需要放行的防火墙端口信息
default_port = ["8080", "8443", "65000-65004"]


class frps_main:

    # 获取frps 的运行状态
    def get_frps_status(self, argv):
        status = self._status_frps()
        return self.__response_json(status)

    # 获取当前服务器的ip 地址
    def get_server_ip(self,argv):
        if os.path.exists('%sdata/server_ip.pl' % plugin_path):
            server_ip = public.readFile('%sdata/server_ip.pl' % plugin_path)
        else:
            server_ip = requests.get('https://ip.iw3c.top').text
            public.writeFile('%sdata/server_ip.pl' % plugin_path,server_ip)
        return self.__response_json(server_ip)

    # 更新frps 的运行状态
    def update_frps_status(self, argv):
        status = ['start', 'stop', 'reload']
        if argv.status in status:
            update = self._update_frps(argv.status)
            return self.__response_json(update)
        else:
            return self.__response_json(None, 500, '请求的参数有误,status 必须是 [start,stop,reload] 中的一种')

    # 读取frps 的运行日志
    def get_frps_log(self, argv):
        log = public.readFile(plugin_path + 'data/log/frps.log')
        return self.__response_json(log)

    # 获取当前插件的配置信息
    def get_global_config(self, argv):
        db_obj = self.__db()
        _configs = db_obj.table('global_config').where("`group` in ('all','frps')", ()).select()
        config = {}
        for _config in _configs:
            config[_config['name']] = _config['value']
        config['plugin_version'] = self.__plugin_version()
        return self.__response_json(config)

    # 读取frps 支持的配置群组信息列表
    def get_frps_config_group_list(self, argv):
        db_obj = self.__db()
        configs = db_obj.table('global_config').where('`group` = ?', ('frps_group')).select()
        list = []
        for i in configs:
            item = {'name': i['name'], 'value': i['value']}
            list.append(item)
        return self.__response_json(list)

    # 读取frps 支持的配置信息列表
    def get_frps_configs_list(self, argv):
        db_obj = self.__db()
        conn = db_obj.table('frps_config')
        if hasattr(argv, "groups"):
            groups = ""
            for group in argv.groups:
                if groups == "":
                    groups = "[" + group
                else:
                    groups = groups + "," + group
            groups = groups + "]"
            conn = conn.where('`group` in ' + groups)
        config = {}
        config_list = conn.select()
        config_group = db_obj.table('global_config').where('`group` = ?', ('frps_group')).select()
        for group in config_group:
            config[group['name']] = {"base": [], "dev": []}
        for c in config_list:
            nconfig = {
                "name": c["name"],
                "content": c["content"],
                "support": c["support"],
                "extend": c["extend"],
                "type": c["type"],
                "help_url": c["help_url"]
            }
            if c['type'] == 'int':
                nconfig['value'] = int(c['value'])
            if c['type'] == 'bool':
                if c['value'] == 'true':
                    nconfig['value'] = 1
                else:
                    nconfig['value'] = 0
            else:
                nconfig['value'] = c['value']
            if c['is_dev'] == 1:
                config[c['group']]['dev'].append(nconfig)
            else:
                config[c['group']]['base'].append(nconfig)
        return self.__response_json(config)

    # 通过配置名查询配置详情
    def get_frps_configs_byname(self, argv):
        val = self._get_config(argv.config_name)
        if val == None:
            return self.__response_json({}, 500, '不存在配置项[' + argv.config_name + "]")
        else:
            return self.__response_json({
                "name": val["name"],
                "content": val["content"],
                "support": val["support"],
                "extend": val["extend"],
                "type": val["type"],
                "help_url": val["help_url"],
                'value': val['value']
            })

    # 批量查询配置项
    def get_frps_config_byname_group(self, argv):
        config_groups = argv.config_groups.split(',')
        configs = []
        for name in config_groups:
            val = self._get_config(name)
            if val != None:
                config = {
                    "name": val["name"],
                    "content": val["content"],
                    "support": val["support"],
                    "extend": val["extend"],
                    "type": val["type"],
                    "help_url": val["help_url"],
                    'value': val['value']
                }
            else:
                config = None
            configs.append(config)
        return self.__response_json(configs)

    # 修改frps 的配置
    def update_frps_config(self, argv):
        result = []
        dict = argv.__dict__
        # 检查端口是否被占用
        for key in dict.keys():
            val = getattr(argv, key)
            if key in configs_checkport:
                cid = self._check_ports(key, val, argv)
                if cid == 1:
                    return self.__response_json({"name": key}, 500,'配置项[%s]的端口号[%s]已经被frps的其他配置占用' % (self._get_config(key)['name'], val))
                if cid == 2:
                    return self.__response_json({"name": key}, 500, '配置项[%s]的端口号[%s]已经被其他进程占用' % (self._get_config(key)['name'], val))
        for key in dict.keys():
            val = getattr(argv, key)
            if key not in ['data', 'client_ip', 's', 't', 'name', 'fun', 'request_time', 'request_token']:
                config_type = self.__get_config_type(key)
                if config_type:
                    self.__update_config_value(key, val, config_type)
                    if key in configs_firewall:
                        if str(val) != "0":
                            # 自动放行防火墙
                            firewall = firewalls.firewalls()
                            get = public.dict_obj()
                            get.port = val
                            get.ps = ('frps [%s] 端口') % self._get_config(key)['name']
                            firewall.AddAcceptPort(get)

                    result.append({"name": key, "msg": "success", 'value': val})
                else:
                    result.append({"name": key, "msg": "配置项不存在"})
        self._reload_frps()
        return self.__response_json(result)

    # 获取frps 的详细运行状态信息
    def get_frps_detail(self, argv):
        status = self._status_frps()
        if not status['running']:
            return self.__response_json({}, 500, 'frp 服务端没有在运行')
        else:
            authorization = 'Basic ' + base64.b64encode(
                (self._get_config('dashboard_user')['value'] + ":" + self._get_config('dashboard_pwd')['value']).encode(
                    'utf-8')).decode()
            headers = {'Authorization': authorization}
            server_info = json.loads(
                requests.get('http://127.0.0.1:' + self._get_config('dashboard_port')['value'] + '/api/serverinfo',
                             headers=headers).text)
            server_info['tcp'] = json.loads(
                requests.get('http://127.0.0.1:' + self._get_config('dashboard_port')['value'] + '/api/proxy/tcp',
                             headers=headers).text)
            server_info['udp'] = json.loads(
                requests.get('http://127.0.0.1:' + self._get_config('dashboard_port')['value'] + '/api/proxy/tcp',
                             headers=headers).text)
            server_info['stcp'] = json.loads(
                requests.get('http://127.0.0.1:' + self._get_config('dashboard_port')['value'] + '/api/proxy/tcp',
                             headers=headers).text)
            server_info['sudp'] = json.loads(
                requests.get('http://127.0.0.1:' + self._get_config('dashboard_port')['value'] + '/api/proxy/tcp',
                             headers=headers).text)
            return self.__response_json(server_info)

    # 获取云端支持的更新切换的frp 版本西悉尼列表
    def get_frp_cloud_versions(self, args):
        frp_version_list = self._get_frp_cloud_version_data()
        versions = []
        for version in frp_version_list['version'].keys():
            versions.append(version)
        versions.sort(reverse=True)
        return self.__response_json(versions)

    # 刷新 云端frps 的缓存列表
    def update_frp_cloud_version(self, argv):
        db_obj = self.__db()
        db_obj.table('global_config').where('name = ?', 'frp_version_cache').update(
            {'value': 0})
        self._get_frp_cloud_version_data()
        return self.__response_json(True)

    # 安装不同版本的frps
    def update_install_frps_version(self, args):
        self._stop_frps()
        task = panelTask.bt_task()
        result = task.create_task('更新frp 内核', 0,
                                  'btpython /www/server/panel/plugin/frps/frps_main.py install ' + args.version,
                                  args.version)
        return self.__response_json(result)

    # 查询指定任务的执行状态
    def get_task_status(self, args):
        task = panelTask.bt_task()
        status = task.get_task_find(args.id)
        return self.__response_json(status)

    # 查询客户端证书信息列表
    def get_cert_list(self, args):
        db_obj = self.__db()
        certs = db_obj.table('tls_cert').field('id,name,create_time').select()
        return self.__response_json(certs)

    # 查询指定证书的详情
    def get_cert_detail(self, args):
        db_obj = self.__db()
        certs = db_obj.table('tls_cert').where('id = ?', args.id).select()[0]
        return self.__response_json(certs)

    # 新建客户端证书
    def create_cert(self, args):
        if os.path.exists('/tmp/frp_cert'):
            os.system('rm -rf /tmp/frp_cert')
        os.mkdir('/tmp/frp_cert')
        ca_crt_path = plugin_path + 'data/tls/ca/ca.crt'
        ca_key_path = plugin_path + 'data/tls/ca/ca.key'
        server_ip = requests.get('https://ip.iw3c.top/').text

        shell = """openssl genrsa -out /tmp/frp_cert/client.key 2048 
openssl req -new -sha256 -key /tmp/frp_cert/client.key -subj "/C=XX/ST=DEFAULT/L=DEFAULT/O=DEFAULT/CN=client.%s.frp.plugin.bt.cn" \
-reqexts SAN -config <(cat /www/server/panel/plugin/frps/data/tls/openssl.cnf <(printf "\\n[SAN]\\nsubjectAltName=DNS:bt.cn,DNS:client.%s.frp.plugin.bt.cn")) \
-out /tmp/frp_cert/client.csr 
openssl x509 -req -days 3650 -in /tmp/frp_cert/client.csr -CA %s -CAkey %s -CAcreateserial  \
-extfile <(printf "subjectAltName=DNS:bt.cn,DNS:client.%s.frp.plugin.bt.cn") \
-out /tmp/frp_cert/client.crt
""" % (server_ip,server_ip,ca_crt_path, ca_key_path,server_ip)
        public.writeFile('/tmp/frp_cert/cert.sh', shell)
        os.system('bash /tmp/frp_cert/cert.sh')
        cert_key = public.readFile('/tmp/frp_cert/client.key')
        cert_crt = public.readFile('/tmp/frp_cert/client.crt')
        cert_csr = public.readFile('/tmp/frp_cert/client.csr')
        db_obj = self.__db()
        cert_id = db_obj.table('tls_cert').insert(
            {'name': args.cert_name, 'cert_key': cert_key, 'cert_crt': cert_crt, 'cert_csr': cert_csr,
             'create_time': int(time.time())})
        return self.__response_json(
            {'cert_id': cert_id, 'cert_key': cert_key, 'cert_crt': cert_crt, 'cert_csr': cert_csr})

    # 删除客户端证书
    def delete_cert(self, args):
        db_obj = self.__db()
        db_obj.table('tls_cert').where('id = ?', args.id).delete()
        return self.__response_json(True)

    # 修改客户端证书
    def update_cert(self, args):
        db_obj = self.__db()
        db_obj.table('tls_cert').where('id = ?', args.id).update({'name': args.cert_name, 'extend': args.cert_extend})
        certs = db_obj.table('tls_cert').where('id = ?', args.id).select()[0]
        return self.__response_json(certs)

    # 读取ca 证书信息
    def get_ca_info(self, args):
        ca_crt = public.readFile(plugin_path + 'data/tls/ca/ca.crt')
        ca_key = public.readFile(plugin_path + 'data/tls/ca/ca.key')
        ca_srl = public.readFile(plugin_path + 'data/tls/ca/ca.srl')
        return self.__response_json({'ca_crt': ca_crt, 'ca_key': ca_key, 'ca_srl': ca_srl})

    # 从数据库里面读取某个配置项目的详情
    def _get_config(self, name):
        db_obj = self.__db()
        configs = db_obj.table("frps_config").where('name = ?', (name)).select()
        if len(configs):
            return configs[0]
        else:
            return None

    # 检查指定的端口是否被占用
    # 0 没有占用
    # 1 被frps 的其他应用占用
    # 2 被其他应用占用
    def _check_ports(self, name, port, argv):
        config = self._get_config(name)
        if config['value'] == str(port):
            return 0
        else:
            db_obj = self.__db()
            configs = db_obj.table("frps_config").where('value = ?', (port)).select()
            for config in configs:
                if config['name'] != name:
                    argv_val = ""
                    if hasattr(argv, config['name']):
                        argv_val = getattr(argv, config['name'])
                    if config['name'] in configs_checkport and argv_val == port:
                        return 1
            if public.check_port_stat(int(port)):
                return 2

    # 安装frps 内核
    def _install_frps(self, download, force=False):
        if not os.path.exists(plugin_path + 'bin/') or force:
            if force:
                os.system(('rm -rf %sbin') % plugin_path)
            os.mkdir(plugin_path + 'bin/')
            print('从云端下载frp[%s]中...' % download['version'])
            os.system("wget %s -O %sbin/%s" % (download['url'], plugin_path, download['name']))
            os.system("cd %sbin && tar -zxvf %sbin/%s" % (plugin_path, plugin_path, download['name']))
            os.remove("%sbin/%s" % (plugin_path, download['name']))
            dir_name = download['name'].replace('.tar.gz', '')
            os.system("rm -rf %sbin/%s/*.ini" % (plugin_path, dir_name))
            os.remove("%sbin/%s/frpc" % (plugin_path, dir_name))
            os.remove("%sbin/%s/LICENSE" % (plugin_path, dir_name))
            public.writeFile("%sbin/%s/version.json" % (plugin_path, dir_name), json.dumps(download))
            os.system("mv %sbin/%s/* %sbin/" % (plugin_path, dir_name, plugin_path))
            os.system("rm -rf %sbin/%s/" % (plugin_path, dir_name))
            print('frps 内核安装成功,版本:' + download['version'])
            db_obj = self.__db()
            db_obj.table('global_config').where('name = ?', 'core_version').update({'value': download['version']})
        else:
            version = json.loads(public.readFile(plugin_path + 'bin/version.json'))['version']
            print('frps 内核已经安装,版本:' + version)

    # 初始话frps 插件
    def _init_frps(self):
        # 新建用于 存放数据,配置的目录
        if not os.path.exists(plugin_path + 'data'):
            os.mkdir(plugin_path + 'data')
            os.mkdir(plugin_path + 'data/conf')
            os.mkdir(plugin_path + 'data/log')
            os.mkdir(plugin_path + 'data/tls')

            # 初始化数据
            db_obj = self.__db()
            fofile = db_obj.fofile(plugin_path + 'db.sql')


            # 设置frps 的全局配置
            db_obj.table('global_config').insert(
                {'name': 'core_version', 'value': '', '`group`': 'all', 'extend': 'frp的内核版本'})
            db_obj.table('global_config').insert(
                {'name': 'run_status', 'value': 'stop', '`group`': 'frps', 'extend': 'frps 设置的运行状态'})
            db_obj.table('global_config').insert(
                {'name': 'run_pid', 'value': '', '`group`': 'frps', 'extend': 'frps 运行的进程号'})

            db_obj.table('global_config').insert(
                {'name': 'frp_version', 'value': '', '`group`': 'version', 'extend': 'frp 云端数据缓存'})
            db_obj.table('global_config').insert(
                {'name': 'frp_version_cache', 'value': '0', '`group`': 'version', 'extend': 'frp 云端数据缓存过期时间'})

            # 设置 frps 的 配置
            db_obj.table('frps_config').where('name = ? ', ('dashboard_user')).update(
                {'value': public.GetRandomString(8)})
            db_obj.table('frps_config').where('name = ? ', ('dashboard_pwd')).update(
                {'value': public.GetRandomString(16)})
            db_obj.table('frps_config').where('name = ? ', ('token')).update(
                {'value': str(uuid.uuid4())})

            firewall = firewalls.firewalls()
            get = public.dict_obj()
            for port in default_port:
                get.port = port
                get.ps = 'frps 默认端口'
                firewall.AddAcceptPort(get)

        print('frps 初始化成功')

    # 启动frps 插件
    def _start_frps(self):
        if self._status_frps()['running']:
            return True
        # 重新编译配置文件
        self._format_config()
        pid = public.ExecShell('nohup ./bin/frps -c ./data/conf/frps.ini & \n echo $! ', None, True, plugin_path)
        pid = re.findall(r"^\d+",pid[0])[0]
        db_obj = self.__db()
        db_obj.table('global_config').where('`group` = ? and `name` = ?', ('frps', 'run_status')).update(
            {'value': 'start'})
        db_obj.table('global_config').where('`group` = ? and `name` = ?', ('frps', 'run_pid')).update(
            {'value': pid})
        try:
            if psutil.pid_exists(int(pid)):
                return True
            else:
                return self._start_force_frps()
        except:
            return self._start_force_frps()

    # 强制启动frps 插件
    # 常规启动失败时使用,将强制杀死服务器上所有 frps 进程
    def _start_force_frps(self):
        if self._status_frps()['running']:
            return True
        # 强制终止所有后台正在运行的frps 进程
        os.system('pkill -9 frps')
        self._format_config()
        # fix 修复 命令中 \n 导致ubuntu 执行失败的bug
        pid = public.ExecShell('nohup ./bin/frps -c ./data/conf/frps.ini &  echo $! ', None, True, plugin_path)
        pid = pid[0].replace("\n", "")
        db_obj = self.__db()
        db_obj.table('global_config').where('`group` = ? and `name` = ?', ('frps', 'run_status')).update(
            {'value': 'start'})
        db_obj.table('global_config').where('`group` = ? and `name` = ?', ('frps', 'run_pid')).update(
            {'value': pid})
        try:
            if psutil.pid_exists(int(pid)):
                return True
            else:
                return False
        except:
            return False

    # 停止frps 进程
    def _stop_frps(self, pid=None):
        if not pid:
            db_obj = self.__db()
            pid = db_obj.table('global_config').where('`group` = ? and `name` = ?', ('frps', 'run_pid')).select()[0][
                'value']
        try:
            if psutil.pid_exists(int(pid)):
                os.system('kill -9 ' + pid)
        except:
            pass
        db_obj.table('global_config').where('`group` = ? and `name` = ?', ('frps', 'run_status')).update(
            {'value': 'stop'})
        return True

    # 重启frps 进程
    def _reload_frps(self):
        self._stop_frps()
        print('停止frps 服务成功')
        return self._start_frps()

    # 获取当前frps 进程的运行状态
    def _status_frps(self):
        db_obj = self.__db()
        status = {}
        status['config'] = \
            db_obj.table('global_config').where('`group` = ? and `name` = ?', ('frps', 'run_status')).select()[0][
                'value']
        status['pid'] = \
            db_obj.table('global_config').where('`group` = ? and `name` = ?', ('frps', 'run_pid')).select()[0]['value']
        if not status['pid']:
            status['running'] = False
        else:
            status['running'] = psutil.pid_exists(int(status['pid']))
        return status

    # 变更当前frps 进程的状态
    # update 可选的值 stop / start / reload
    def _update_frps(self, update):
        if update == 'stop':
            return self._stop_frps()
        if update == 'reload':
            return self._reload_frps()
        if update == 'start':
            return self._start_frps()

    # 重新渲染frps 的配置文件
    def _format_config(self):
        config = """# 本配置文件由宝塔面包 frp 服务端插件自动生成
# 本配置文件会在每次启动时自动更新,请不要手动修改该配置文件
# 生成时间 ： %s

[common]
""" % public.format_date()
        db_obj = self.__db()
        config_list = db_obj.table('frps_config').select()
        for c in config_list:
            if not c['support']:
                c['support'] = ''
            if not c['default']:
                c['default'] = ''
            if not c['value']:
                c['value'] = ''
            config = config + "\n # 配置项: " + c['name'] + "\n # 参数类型: " + c['type'] + '\n # 默认值: ' + c['default']
            config = config + "\n # 可选值: " + c['support'] + "\n # 用途: " + c['content']
            if c['extend']:
                config = config + '\n # 备注: ' + c['extend']
            if c['help_url']:
                config = config + '\n # 参考: ' + c['help_url']
            if c['value'] != "0" and c['value'] != "":
                config = config + ("\n %s = %s\n" % (c['name'], c['value']))
            else:
                config = config + ("\n# %s = %s\n" % (c['name'], c['value']))

        public.writeFile(plugin_path + 'data/conf/frps.ini', config)
        print('重新渲染配置文件成功,date:' + public.format_date())
        return config

    # 从云端读取frps 最新的可用版本的信息
    # 相关数据会被缓存 24 小时
    def _get_frp_cloud_version_data(self):
        db_obj = self.__db()
        frp_versions_cache = int(
            db_obj.table('global_config').where('name = ?', 'frp_version_cache').select()[0]['value'])
        if frp_versions_cache < int(time.time()):
            frp_versions = None
        else:
            frp_versions = json.loads(
                db_obj.table('global_config').where('name = ?', 'frp_version').select()[0]['value'])
        if frp_versions:
            return frp_versions
        else:
            try:
                resp = requests.get('https://cdn.iw3c.com.cn/bt-plugin/frp/data.json?t=' + str(int(time.time())))
                data = json.loads(resp.text)
                db_obj.table('global_config').where('name = ?', 'frp_version').update({'value': json.dumps(data)})
                db_obj.table('global_config').where('name = ?', 'frp_version_cache').update(
                    {'value': str(int(time.time()) + 3600 * 24)})
            except:
                frp_versions = db_obj.table('global_config').where('name = ?', 'frp_version').select()[0]['value']
                if frp_versions:
                    data = json.loads(frp_versions)
                else:
                    data = None
            return data

    # 从云端获取frpc的下载地址和版本信息数据
    def _get_frps_cloud_download(self, argv):
        frp_version_list = self._get_frp_cloud_version_data()
        if hasattr(argv, 'version'):
            _version = argv.version
        else:
            _version = frp_version_list['last_version']
        if _version in frp_version_list['version']:
            version = _version
        else:
            version = frp_version_list['last_version']
        download = frp_version_list['version'][version]['linux']
        download['version'] = version
        return download

    # 读取某个配置项目的数据类型
    def __get_config_type(self, config):
        db_obj = self.__db()
        configs = db_obj.table("frps_config").where('name = ?', (config)).field('type').select()
        if len(configs):
            return configs[0]['type']
        else:
            return False

    # 修改某个配置项的值
    def __update_config_value(self, name, value, type):
        if type == 'bool':
            if int(value) == 1:
                value = 'true'
            else:
                value = 'false'
        db_obj = self.__db()
        return db_obj.table('frps_config').where("name = ?", name).update({"value": value})

    # 读取当前插件的版本
    def __plugin_version(self):
        info = json.loads(public.readFile(plugin_path + '/info.json'))
        return info['versions']

    # 统一响应json 格式的消息
    def __response_json(self, data, code=0, msg=''):
        response = {"code": code, "msg": msg, "data": data}
        return response

    # 取插件数据库通用对象
    def __db(self):
        obj = db.Sql()
        obj.dbfile(db_path)
        return obj


if __name__ == '__main__':

    argv = sys.argv
    _func = ['start', 'stop', 'restart', 'uninstall', 'install', 'init', 'status', 'config']
    try:
        func = argv[1]
        if not func in _func:
            print('[ERROR]: Please input corrent function name ! ')
            print('Support function: start/stop/restart/install/unistall/init/status/config')
            exit(0)
    except:
        print('[ERROR]: Please input corrent function name ! ')
        print('Support function: start/stop/restart/install/unistall/init/status/config')
        exit(0)

    frps = frps_main()

    # 安装插件内核
    if func == 'install':
        if len(argv) != 3:
            frps._install_frps(frps._get_frps_cloud_download(public.dict_obj()))
        else:
            get = public.dict_obj()
            get.version = argv[2]
            frps._install_frps(frps._get_frps_cloud_download(get), True)

    # 初始化插件
    if func == 'init':
        frps._init_frps()

    # 渲染配置
    if func == 'config':
        frps._format_config()

    # 运行状态
    if func == 'status':
        status = frps._status_frps()
        if not status['pid']:
            pid = ""
        if status['running'] == True:
            running = '运行中'
        else:
            running = '已停止'
            pid = ""
        print('frps 配置状态：' + status['config'])
        print('frps 实际状态：' + running)
        print('frps 进程号:' + pid)

    # 启动插件
    if func == 'start':
        s = frps._start_frps()
        if s:
            print('启动frps 成功')
        else:
            print('重启frps 失败')

    # 停止插件
    if func == 'stop':
        s = frps._stop_frps()
        if s:
            print('停止frps 成功')
        else:
            print('停止frps 失败')

    # 重启插件
    if func == 'restart':
        s = frps._reload_frps()
        if s:
            print('重启frps 成功')
        else:
            print('重启frps 失败')

