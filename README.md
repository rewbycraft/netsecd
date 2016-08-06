# OpenStack Network SecurityGroups Daemon

This is a small daemon to use Neutron's per-port security groups feature to implement per-network security groups.

## Dependencies

The program depends on python3-keystoneclient, python3-neutronclient, python3-oslo-config, python3-oslo-log.

## Configuration

Please look at the netsec.conf file in the repository for instructions on how to configure the daemon.

## Running

I personally recommend using supervisord. And have included a config as supervisord.conf.sample

## Support

You can get support from my by emailing contact at roelf dot org or by visiting my IRC channel #rewbycraft at EsperNet, HackINT or SynIRC.

## NOTE

This repository is mirrored on github, the original source can be found at https://git.roelf.org/projects/PUB/repos/netsecd/browse

