#!/usr/bin/python
# -*- coding: utf-8 -*-
"""

    IPMItool/freeipmi MQTT publisher

    Created on Fri Dec 19 12:20:56 2014

    @author: francesco.beneventi@unibo.it

"""
import re
import os
import sys
import time
import math
import json
import logging
from logging.handlers import RotatingFileHandler
from concurrent_log_handler import ConcurrentRotatingFileHandler
import argparse
import configparser
from subprocess import Popen, PIPE
import paho.mqtt.client as mqtt
import multiprocessing as mp
import signal
from daemon import Daemon


LOGFILE_SIZE_B = 5 * 1024 * 1024
LOG_LEVEL = logging.WARNING
BACKUP_COUNT = 2
SLOWED_START_INTERVAL = 60
SLOWED_START_GROUP_SIZE = 50

class IpmiPub():
    """
        IPMI->MQTT publisher
    """

    CMD_SDR_TYPE_FAN = 'sdr type fan'
    CMD_SENSOR_GET_ID = 'sensor get'
    CMD_ELIST_FULL = 'sdr elist full'
    CMD_FREEIPMI = '--ipmimonitoring-legacy-output'
    CMD_OPENBMCTOOL = 'sensors print'

    def __init__(self, hostinfo, tool_path='ipmitool', mqtt_base_topic='', timeout=None):
        self.TOOL_PATH = tool_path
        self.hostinfo = hostinfo
        self.topic_mask = '{}/node/{}/rack/{}/chassis/{}/slot/{}/plugin/ipmi_pub/chnl/data'
        self.mqtt_topic = self.build_base_topic(mqtt_base_topic)
        self.timeout = timeout
        self.client = None
        mp.current_process().name = self.hostinfo['hostname']

    def build_base_topic(self, mqtt_base_topic):
        """Build base topic"""
        topic = self.topic_mask
        rack = chassis = slot = 'NA'
        server_coord = [str(number) for number in re.findall(r"\d+", self.hostinfo['hostname'])]
        if len(server_coord) == 1:
            slot = server_coord[0]
        if len(server_coord) == 2:
            rack, slot = server_coord
        if len(server_coord) == 3:
            rack, chassis, slot = server_coord

        return topic.format(mqtt_base_topic,
                            self.hostinfo['hostname'],
                            rack,
                            chassis,
                            slot)

    def setup_cmd(self, tool_par):
        """
            Execute ipmitool command and return the shell output (string)
        """
        cmd = ""

        if self.TOOL_PATH == 'ipmitool':
            cmd = self.TOOL_PATH
            cmd += (' -I lanplus')
            cmd += (' -H %s' % self.hostinfo['bmc_ip'])
            if self.hostinfo['username'] is not None:
                cmd += (' -U %s' % self.hostinfo['username'])
            if self.hostinfo['password'] is not None:
                cmd += (' -P %s' % self.hostinfo['password'])
            if self.hostinfo['custom_opt'] is not None:
                cmd += (' %s' % self.hostinfo['custom_opt'])           
            cmd += (' ')
            cmd += (IPMI_OPTIONS)

        if self.TOOL_PATH == 'ipmi-sensors':
            cmd = self.TOOL_PATH
            cmd += (' -h %s' % self.hostinfo['bmc_ip'])
            if self.hostinfo['username'] is not None:
                cmd += (' -u %s' % self.hostinfo['username'])
            if self.hostinfo['password'] is not None:
                cmd += (' -p %s' % self.hostinfo['password'])
            cmd += (' ')
            cmd += (IPMI_OPTIONS)

        if self.TOOL_PATH == 'openbmctool':
            cmd = self.TOOL_PATH
            cmd += (' -H %s' % self.hostinfo['bmc_ip'])
            if self.hostinfo['username'] is not None:
                cmd += (' -U %s' % self.hostinfo['username'])
            if self.hostinfo['password'] is not None:
                cmd += (' -P %s' % self.hostinfo['password'])
            cmd += (' ')
            cmd += (IPMI_OPTIONS)

        cmd += (' %s' % tool_par)
        cmd += (' 2>&1')

        return cmd

    def run_cmd(self, cmd):
        """Execute command and return output"""
        output = ''

        if self.hostinfo['password'] is not None:
            logger.debug("[%s] Executing command: %s", mp.current_process().name, cmd.replace(self.hostinfo['password'], '*' * 8))
        else:
            logger.debug("[%s] Executing command: %s", mp.current_process().name, cmd)

        try:
            if self.timeout:
                cmd = ('timeout %s ' % self.timeout) + cmd
            child = Popen(cmd, shell=True, text=True, stdout=PIPE)
            output = child.communicate()[0]
            if child.returncode != 0:
                logger.error("[%s] Error in run_cmd(): %s - cmd: %s - ret %s", mp.current_process().name, output, cmd, child.returncode)
        except Exception:
            logger.exception("[%s] Exception in run_cmd(): ", mp.current_process().name)

        return output

    def parse_cmd_output(self, cmd_output):
        """
            Parse cmd output.
            Return a dictionary of IPMI sampled values
        """
        sens_val = {}
        lines = cmd_output.split('\n')
        tmpline = []
        for line in lines:
            logger.debug("[%s] Split result: %s", mp.current_process().name, line.split('|')[0])
            tmpline = line.split('|')
            if len(tmpline) > 1:
                if self.TOOL_PATH == 'ipmitool':
                    try:
                        r_key = tmpline[0].strip() + '_' + tmpline[1].strip()
                        if r_key in list(IPMI_RENAME_LABEL.keys()):
                            tmpline[0] = IPMI_RENAME_LABEL[r_key]
                        fields = tmpline[4].split(' ')
                        val = float(fields[1])
                        units = str(''.join(fields[2:]).rstrip())
                        sens_val[tmpline[0].strip()] = [val, units]
                    except Exception:
                        continue
                elif self.TOOL_PATH == 'ipmi-sensors':
                    try:
                        val = float(tmpline[4].strip())
                        sens_val[tmpline[1].strip()] = val
                    except Exception:
                        continue
                elif self.TOOL_PATH == 'openbmctool':
                    try:
                        val = float(tmpline[3].strip())
                        sens_val[tmpline[0].strip()] = val
                    except Exception:
                        continue

        logger.debug("[%s] Parsed metrics: %s", mp.current_process().name, sens_val)
        if IPMI_SENS_TAGS != ['']:
            return {k: v for k, v in sens_val.items() if k in IPMI_SENS_TAGS}

        return sens_val

    def run(self):
        """
            Daemon main code loop
        """
        info_txt = "[%s] Binding IPMI publisher [%s] to: Host=%s BMC_IP=%s tool_path=%s" % (
            mp.current_process().name, mp.current_process().name, self.hostinfo['hostname'], 
            self.hostinfo['bmc_ip'], self.TOOL_PATH)
        
        logger.info(info_txt)

        self.client = mqtt.Client()
        if MQTT_USER:
            self.client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
        self.client.on_connect = self.on_connect
        logger.info('[%s] Connecting to the MQTT broker...', mp.current_process().name)
        self.client.connect(MQTT_BROKER, port=int(MQTT_PORT))
        logger.info('[%s] MQTT start looping', mp.current_process().name)
        self.client.loop_start()

        if self.TOOL_PATH == 'ipmitool':
            cmd = self.CMD_ELIST_FULL
        elif self.TOOL_PATH == 'ipmi-sensors':
            cmd = self.CMD_FREEIPMI
        elif self.TOOL_PATH == 'openbmctool':
            cmd = self.CMD_OPENBMCTOOL

        cmd = self.setup_cmd(cmd)

        logger.info("[%s] Running... ", mp.current_process().name)
        while True:
            time.sleep(float(TS) - (time.time() % float(TS)))
            timestamp = time.time()
            ipmiout = self.run_cmd(cmd)
            sens_dict = self.parse_cmd_output(ipmiout)
            for k, v in sens_dict.items():
                mqtt_str = str(v[0])
                mqtt_str += (";%.3f" % (math.floor(timestamp * 100) / 100))
                mqtt_tpc = self.mqtt_topic
                mqtt_tpc += '/units/' + (v[1]).replace(' ', '_').replace('+', '_').replace('#', '_').replace('/', '_')
                mqtt_tpc += '/' + (k).replace(' ', '_').replace('+', '_').replace('#', '_').replace('/', '_')
                logger.debug("[%s] Topic: %s", mp.current_process().name, mqtt_tpc)
                logger.debug("[%s] Payload: %s", mp.current_process().name, mqtt_str)
                try:
                    self.client.publish(mqtt_tpc, payload=str(mqtt_str), qos=0, retain=False)
                except Exception:
                    logger.exception("[%s] Exception in MQTT publish: ", mp.current_process().name)
                    continue

    def on_connect(self, client, userdata, flags, rc):
        """MQTT connection callback"""
        if int(rc) != 0:
            logger.error('[%s] Error in connect. Result code: %s', mp.current_process().name, str(rc))
            logger.info('[%s] Closing the MQTT connection', mp.current_process().name)
            self.client.disconnect()
        else:
            logger.info("[%s] Connected with result code: %s", mp.current_process().name, str(rc))


def get_ipmi_hosts(conf_file, username, passw):
    """
       Build BMC host list
    """
    ipmi_db = []
    try:
        with open(conf_file) as f:
            for lines in f:
                if '#' in lines:
                    continue
                item = {}
                line = lines.strip().split(';')
                item['bmc_ip'] = line[0]
                item['hostname'] = line[1]
                item['username'] = line[2] if line[2] else username
                item['password'] = line[3] if line[3] else passw
                item['custom_opt'] = line[4] if line[4] else None
                ipmi_db.append(item)
    except IOError as e:
        logger.error('%s', e)
        sys.exit(1)

    return ipmi_db


def worker(hostinfo):
    """
        Worker process code
    """
    daemon = IpmiPub(hostinfo, tool_path='ipmitool', mqtt_base_topic=MQTT_TOPIC)
    return daemon.run()


def kill_child_processes(signum, frame):
    """
        Handle sigterm
    """
    parent_id = os.getpid()
    ps_command = Popen("ps -o pid --ppid %d --noheaders" % parent_id, shell=True, text=True, stdout=PIPE)
    ps_output = ps_command.stdout.read()
    retcode = ps_command.wait()
    for pid_str in ps_output.strip().split("\n")[:-1]:
        os.kill(int(pid_str), signal.SIGTERM)
    sys.exit(0)


if __name__ == '__main__':
    config = configparser.RawConfigParser()
    config.read('ipmi_pub.conf')
    MQTT_BROKER = config.get('MQTT', 'MQTT_BROKER')
    MQTT_PORT = config.get('MQTT', 'MQTT_PORT')
    MQTT_TOPIC = config.get('MQTT', 'MQTT_TOPIC')
    MQTT_USER = config.get('MQTT', 'MQTT_USER')
    MQTT_PASSWORD = config.get('MQTT', 'MQTT_PASSWORD')
    IPMI_SENS_TAGS = config.get('IPMI', 'IPMI_SENS_TAGS').split(',')
    IPMI_SENS_TAGS = [(item).strip() for item in IPMI_SENS_TAGS]  
    IPMI_OPTIONS = config.get('IPMI', 'IPMI_OPTIONS')
    IPMI_RENAME_LABEL = json.loads(config.get('IPMI', 'IPMI_RENAME_LABEL'))
    TS = config.getfloat('Daemon', 'TS')
    LOGFILE = config.get('Daemon', 'LOG_FILENAME')
    LOG_LEVEL = config.get('Daemon', 'LOG_LEVEL')
    PID_FILENAME = config.get('Daemon', 'PID_FILENAME')
    BMCIP_FILENAME = config.get('Daemon', 'BMCIP_FILENAME')
    BMC_USERNAME = config.get('Daemon', 'BMC_USERNAME')
    BMC_PASSWORD = config.get('Daemon', 'BMC_PASSWORD')

    parser = argparse.ArgumentParser()
    parser.add_argument("runmode", choices=["run", "start", "stop", "restart"], help="Run mode")
    parser.add_argument("-b", help="IP address of the MQTT broker")
    parser.add_argument("-p", help="Port of the MQTT broker")
    parser.add_argument("-t", help="MQTT topic")
    parser.add_argument("-s", help="Sampling time (seconds)")
    parser.add_argument("-x", help="pid filename")
    parser.add_argument("-l", help="log filename")
    parser.add_argument("-L", help="log level")
    parser.add_argument("-f", help="BMC ip adresses filename")
    parser.add_argument("-U", help="BMC username")
    parser.add_argument("-P", help="BMC password")
    parser.add_argument("-m", help="MQTT username")
    parser.add_argument("-r", help="MQTT password")
    parser.add_argument("-o", help="Additional options for the IPMI command")
    parser.add_argument("-n", help="Rename IPMI labels (dictionary)")

    args = parser.parse_args()

    if args.b:
        MQTT_BROKER = args.b
    if args.p:
        MQTT_PORT = args.p
    if args.t:
        MQTT_TOPIC = args.t
    if args.m:
        MQTT_USER = args.m
    if args.r:
        MQTT_PASSWORD = args.r
    if args.s:
        TS = float(args.s)
    if args.x:
        PID_FILENAME = args.x
    if args.l:
        LOGFILE = args.l
    if args.L:
        LOG_LEVEL = args.L
    if args.f:
        BMCIP_FILENAME = args.f
    if args.U:
        BMC_USERNAME = args.U
    if args.P:
        BMC_PASSWORD = args.P
    if args.o:
        IPMI_OPTIONS = args.o
    if args.n:
        IPMI_RENAME_LABEL = args.n

    logger = logging.getLogger("root")
    handler = ConcurrentRotatingFileHandler(LOGFILE, mode='a', maxBytes=LOGFILE_SIZE_B, backupCount=BACKUP_COUNT)
    log_formatter = logging.Formatter(fmt='%(levelname)s - %(asctime)s - %(name)s - %(message)s', datefmt='%d/%m/%Y %H:%M:%S')
    handler.setFormatter(log_formatter)
    logger.addHandler(handler)
    logger.setLevel(LOG_LEVEL)
    if args.runmode == 'run':
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(log_formatter)
        logger.addHandler(handler)

    logger.debug('IPMI_SENS_TAGS published: %s', IPMI_SENS_TAGS)
    ipmi_hosts = get_ipmi_hosts(BMCIP_FILENAME, BMC_USERNAME, BMC_PASSWORD)

    daemon = Daemon(PID_FILENAME)

    if args.runmode == 'stop':     
        print("Terminating daemon...")
        daemon.stop()
        sys.exit(0)
    elif args.runmode in ['run', 'start', 'restart']:
        print("Init workers")
        original_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
        original_sigterm_handler = signal.signal(signal.SIGTERM, kill_child_processes)

        if args.runmode == 'start':
            print("Daemonize..")
            daemon.start()
        elif args.runmode == 'restart':
            print("Restarting Daemon..")
            daemon.restart()
        else:
            pass

        pool = mp.Pool(len(ipmi_hosts))
        signal.signal(signal.SIGINT, original_sigint_handler)

        print("Starting jobs...")
        i = 1
        for hostinfo in ipmi_hosts:
            pool.apply_async(worker, args=(hostinfo,))
            if not (i % SLOWED_START_GROUP_SIZE):
                time.sleep(SLOWED_START_INTERVAL)
            i += 1

        try:
            signal.pause()
        except KeyboardInterrupt:
            logging.info("[Main]: Received SIGTERM..")
            print(" Terminating jobs...")
            pool.terminate()
            pool.join()
            logging.info("[Main]: Terminated all workers..")
        else:
            print("Normal termination")
            pool.close()
            pool.join()
            print("Joining...")
    else:
        print("Unknown command")
        sys.exit(2)
    logging.info("[Main]: Exiting..")
    sys.exit(0)
