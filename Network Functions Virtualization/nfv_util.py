# cluster state data structure which will keep track of all the containers in the topology, chains, flow mapping
class ClusterState:
    def __init__(self):
        # Keeps track of chain information {chain_id: CHAIN}
        self.CHAINS = {}
        # Port 1 is reserved for switch to switch
        # Ports 2 & 3 are reserved for 2 src and 2 dst on each switch
        self.SWITCH_1_PORT_INDEX = 4
        self.SWITCH_2_PORT_INDEX = 4
        # used for NF naming purposes
        self.FW_INDEX = 1
        self.NAT_INDEX = 1
        # used to keep flow affinity 
        # {(src_ip, dst_ip, src_tcp_port, dst_tcp_port): (chain_id, chain_fw_index, chain_nat_index)}
        self.FLOW_TO_CHAIN_MAPPING = {}

        # Creating default src and dst hosts
        src1 = SRC("192.168.1.2", "00:00:00:00:00:01", 1, 2)
        src2 = SRC("192.168.1.3", "00:00:00:00:00:02", 1, 3)

        self.SRC_POOL = [src1, src2]

        dst1 = DST("143.12.131.92", "00:00:00:00:01:01", 2, 2)
        dst2 = DST("143.12.131.93", "00:00:00:00:01:02", 2, 3)
        self.DST_POOL = [dst1, dst2]

        # Used for ARP indexing
        self.CONTAINER_POOL = self.SRC_POOL + self.DST_POOL

# class to store src information
class SRC:
    def __init__(self, OUT_IP, OUT_MAC, SWITCH_DPID, OUT_PORT):
        self.OUT_IP = OUT_IP
        self.OUT_MAC = OUT_MAC
        self.SWITCH_DPID = SWITCH_DPID
        self.OUT_PORT = OUT_PORT

    def __str__(self):
        return f"src host - ip: {self.OUT_IP}, mac: {self.OUT_MAC}, port: {self.OUT_PORT}"

    def get_ips(self):
        return [self.OUT_IP]
    
    def get_mac_addresses(self):
        return [self.OUT_MAC]
    
# class to store dst information
class DST:
    def __init__(self, IN_IP, IN_MAC, SWITCH_DPID, IN_PORT):
        self.IN_IP = IN_IP
        self.IN_MAC = IN_MAC
        self.SWITCH_DPID = SWITCH_DPID
        self.IN_PORT = IN_PORT

    def __str__(self):
        return f"dst host - ip: {self.IN_IP}, mac: {self.IN_MAC}, port: {self.IN_PORT}"
    
    def get_ips(self):
        return [self.IN_IP]
    
    def get_mac_addresses(self):
        return [self.IN_MAC]

# class to store chain information, should be created when receiving a register request 
class CHAIN:
    # initialize chain with parameters that are given with the register API
    def __init__(self, NF_CHAIN, SRC, DST, FW_LAUNCH_SCRIPT, NAT_LAUNCH_SCRIPT):
        self.NF_CHAIN = NF_CHAIN
        self.SRC = SRC
        self.DST = DST

        # used for round robin selection of NFs
        self.FW_INDEX = 0
        self.NAT_INDEX = 0

        # keeps track of NFs that belong to this chain
        self.FW_POOL = []
        self.NAT_POOL = []

        self.FW_LAUNCH_SCRIPT = FW_LAUNCH_SCRIPT
        self.NAT_LAUNCH_SCRIPT = NAT_LAUNCH_SCRIPT
    
    def __str__(self):
        return f"chain - src: {self.SRC}, dst: {self.DST}"

# class to store a NFs information, should be created when receiving a launch request
# this class should be added to their respective chain's FW or NAT pool depending on type
class FW:
    def __init__(self, NAME, IN_PORT, OUT_PORT, IN_MAC, OUT_MAC):
        self.NAME = NAME,
        self.SWITCH_DPID = 1
        self.IN_PORT = IN_PORT
        self.OUT_PORT = OUT_PORT
        self.IN_MAC = IN_MAC
        self.OUT_MAC = OUT_MAC

    def __str__(self):
        return f"{self.NAME} - in_port: {self.IN_PORT}, in_mac: {self.IN_MAC} out_port: {self.OUT_PORT}, out_mac: {self.OUT_MAC}"

    def get_ips(self):
        return []
    
    # returns mac addresses [eth0, eth1]
    def get_mac_address(self):
        return [self.IN_MAC, self.OUT_MAC]

class NAT:
    def __init__(self, NAME, IN_PORT, OUT_PORT, IN_MAC, OUT_MAC, IN_IP, OUT_IP):
        self.NAME = NAME
        self.SWITCH_DPID = 2
        self.IN_PORT = IN_PORT
        self.OUT_PORT = OUT_PORT
        self.IN_MAC = IN_MAC
        self.OUT_MAC = OUT_MAC
        self.IN_IP = IN_IP
        self.OUT_IP = OUT_IP

    def __str__(self):
        return f"{self.NAME} - in_port: {self.IN_PORT}, in_mac: {self.IN_MAC} out_port: {self.OUT_PORT}, out_mac: {self.OUT_MAC}"

    # returns ip addresses [eth0, eth1]
    def get_ips(self):
        return [self.IN_IP, self.OUT_IP]

    # returns mac addresses [eth0, eth1]
    def get_mac_addresses(self):
        return [self.MAC, self.MAC]