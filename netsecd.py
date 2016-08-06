#!/usr/bin/env python3
import sched
import time
from oslo_config import cfg
from oslo_log import log as logging
from neutronclient.v2_0 import client as neutron_client
from keystoneclient.auth.identity import v3 as keystone_v3
from keystoneclient import session as keystone_session

LOG = logging.getLogger("netsec")
CONF = cfg.CONF
scheduler = sched.scheduler(time.time, time.sleep)

common_opts = [
    cfg.ListOpt('networks', required=True, help='List of networks to monitor.'),
    cfg.IntOpt('interval', required=False, default=60, help='Interval in seconds.')
]

network_group_opts = [
    cfg.ListOpt('securitygroups', required=True, help='The security group to apply. (id only)'),
    cfg.ListOpt('exempt', required=False, default=[], help='Port IDs that are exempt.'),
    cfg.ListOpt('owners', required=False, default=['compute:None'], help='Only affect ports owned by one of these.'),
    cfg.BoolOpt('delete_others', required=False, default=True, help='Delete security groups that aren\'t in the securitygroups list.')
]

keystone_opts = [
    cfg.StrOpt('username', required=True),
    cfg.StrOpt('password', required=True),
    cfg.StrOpt('user_domain_name', required=False, default="default"),
    cfg.StrOpt('project_domain_name', required=False, default="default"),
    cfg.StrOpt('project_name', required=True),
    cfg.StrOpt('auth_url', required=True),
]

#Registe config options
def do_config():
    CONF.register_opts(common_opts)
    logging.register_options(CONF)
    keystone_group = cfg.OptGroup(name='keystone', help='Authentication parameters for keystone')
    CONF.register_group(keystone_group)
    CONF.register_opts(keystone_opts, keystone_group)
    CONF(default_config_files=['netsec.conf'])
    logging.setup(CONF, "netsec")
    for netid in CONF.networks:
        grp = cfg.OptGroup(name=('network:%s' % (netid)))
        CONF.register_group(grp)
        CONF.register_opts(network_group_opts, grp)
    LOG.info("Finished parsing config files.")

def setup_neutron_client():
    LOG.info("Attempting to get token from keystone...")
    auth = keystone_v3.Password(username=CONF.keystone.username, password=CONF.keystone.password,
            user_domain_name=CONF.keystone.user_domain_name, project_domain_name=CONF.keystone.project_domain_name,
            project_name=CONF.keystone.project_name, auth_url=("%s/v3" % (CONF.keystone.auth_url)))
    session = keystone_session.Session(auth=auth)
    global NEUTRON
    NEUTRON = neutron_client.Client(session=session)
    LOG.info("Got token!")

def process_all_networks():
    LOG.debug("Performing scan...")
    for network_id in CONF.networks:
        LOG.debug("Processing network %s..." % (network_id))
        network_config = CONF['network:'+network_id]
        ports = NEUTRON.list_ports(network_id=network_id)
        if not "ports" in ports:
            LOG.error("Weird response from neutron.")
            continue
        ports = ports["ports"]
        LOG.debug("Found %i ports on network." % (len(ports)))
        for port in ports:
            LOG.debug("Processing port %s..." % (port["id"]))
            if not port['port_security_enabled']:
                LOG.debug("Skipping port with port_security disabled.")
                continue
            if port['id'] in network_config.exempt:
                LOG.debug("Skipping exempted port.")
                continue
            if not (port["device_owner"] in network_config.owners):
                LOG.debug("Skipping port with non-affected owner %s." % (port["device_owner"]))
                continue
            if network_config.delete_others:
                if set(port["security_groups"]) != set(network_config.securitygroups):
                    LOG.info("Overriding security groups on port %s..." % (port["id"]))
                    NEUTRON.update_port(port["id"], {'port': {'security_groups': network_config.securitygroups}})
            else:
                if not set(network_config.securitygroups).issubset(port["security_groups"]):
                    LOG.info("Appending missing security groups to port %s..." % (port["id"]))
                    new_securitygroups = port["security_groups"] + list(set(network_config.securitygroups) - set(port["security_groups"]))
                    NEUTRON.update_port(port["id"], {'port': {'security_groups': new_securitygroups}})
    scheduler.enter(CONF.interval, 1, process_all_networks, ())

if __name__ == '__main__':
    do_config()
    setup_neutron_client()
    LOG.info("Network SecurityGroups Daemon is now running!")
    process_all_networks()
    scheduler.run()
