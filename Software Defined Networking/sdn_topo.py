import json
from mininet.topo import Topo
from mininet.link import TCLink
 
class SimpleTopo(Topo):
    "Simple loop topology"
 
    def __init__(self):
        "Create custom loop topo."
 
        # Initialize topology
        Topo.__init__(self)
 
        # Load link config
        self.topo = self.load_json_config('config/link_config.json')

        # add switches
        switches = [self.addSwitch(switch) for switch in self.topo['switches']]

        # add hosts
        hosts = [self.addHost(host) for host in self.topo['hosts']]

        # add links
        for link in self.topo['links']:
            configuration = dict(bw=link["bandwidth"], delay=str(link["latency"])+"ms")
            src, src_port = link["input_port"].split("-")
            dst, dst_port = link["output_port"].split("-")
            self.addLink(src, dst, int(src_port), int(dst_port), cls=TCLink, **configuration)
 
    # load json config file
    def load_json_config(self, filename):
        with open(filename, "r") as f:
            config_options = json.load(f)
        return config_options
        
topos = {'topology': (lambda: SimpleTopo())}
