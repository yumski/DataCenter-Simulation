from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet.packet import Packet
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.arp import arp
from ryu.ofproto import ether
from ryu.lib.packet.tcp import tcp
from ryu.lib.packet.ipv4 import ipv4
from ryu.app.wsgi import ControllerBase, WSGIApplication, route

import json
import subprocess
import nfv_util
from webob import Response


class ProjectSDNController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(ProjectSDNController, self).__init__(*args, **kwargs)
        print ("Initializing RYU controller app")
        wsgi = kwargs['wsgi']
        wsgi.register(ProjectRESTController,
            {"ProjectRESTController": self}
        )

        print("Initializing Cluster State")
        self.cluster_state = nfv_util.ClusterState()

        self.IP_TO_MAC_MAPPING = {}

        for container in self.cluster_state.CONTAINER_POOL:
            self.IP_TO_MAC_MAPPING[container.get_ips()[0]] = container.get_mac_addresses()[0]


    # SDN Controller    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        print ("In switch_features_handler")
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow_init(datapath, 0, match, actions)

    def add_flow_init(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def send_arp_reply(self, datapath, src_mac, src_ip, dst_mac, dst_ip, out_port):
        opcode = 2
        e = ethernet(dst_mac, src_mac, ether.ETH_TYPE_ARP)
        a = arp(1, 0x0800, 6, 4, opcode, src_mac, src_ip, dst_mac, dst_ip)
        p = Packet()
        p.add_protocol(e)
        p.add_protocol(a)

        print("------SENT ARP PACKET-------")
        print(p.get_protocol(arp))
        print()
        
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port, 0)]
        out = datapath.ofproto_parser.OFPPacketOut (
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg

        # Extracting packet from incoming pkt_in msg
        packet = Packet(msg.data)
        ether_frame = packet.get_protocol(ethernet)
        try:
            if ether_frame.ethertype == ether.ETH_TYPE_ARP:
                dp = msg.datapath
                in_port = msg.match['in_port']
                self.handle_arp(dp, packet, ether_frame, in_port)
                return 0

            self.handle_packet(msg)

        except Exception as e:
            print ("Exception occurred: ", str(e))

    # Function to handle packets belonging to ARP protocol
    def handle_arp(self, datapath, packet, ether_frame, in_port):
        arp_packet = packet.get_protocol(arp)

        if arp_packet.opcode == 1: # Send an ARP Response for the incoming Request
            # Determine the MAC Address for IP Address being looked up
            # Determine the out port to send the ARP Response 
            
            print("------RECEIVED ARP PACKET-------")
            print(arp_packet)
            print(f"dpid: {datapath.id} in_port: {in_port}")
            print()

            # the destination ip's mac is the new src
            src_mac = self.IP_TO_MAC_MAPPING.get(arp_packet.dst_ip, None)

            if src_mac == None:
                print(f"Couldn't find dst_ip: {arp_packet.dst_ip} in mapping")
                return

            # dst ip is now the src
            src_ip = arp_packet.dst_ip
            # src is now the dst
            dst_mac = ether_frame.src
            dst_ip = arp_packet.src_ip

            # Call helper function to create and send ARP Response
            self.send_arp_reply(datapath, src_mac, src_ip, dst_mac, dst_ip, in_port)
        else:
            # We don't expect to receive ARP replies, so do nothing
            pass

    def handle_packet(self, msg):
        # get the different protocol packets
        packet = Packet(msg.data)
        tcp_packet = packet.get_protocol(tcp)
        ether_frame = packet.get_protocol(ethernet)
        ip_packet = packet.get_protocol(ipv4)

        in_port = msg.match["in_port"]
        datapath = msg.datapath
        parser = datapath.ofproto_parser

        if tcp_packet == None:
            return
        
        print("------RECEIVED TCP PACKET-------")
        print(packet)
        print(f"dpid: {datapath.id} in_port: {in_port}")
        print()

        # get flow information
        src_ip = ip_packet.src
        dst_ip = ip_packet.dst
        src_tcp_port = tcp_packet.src_port
        dst_tcp_port = tcp_packet.dst_port

        flow = (src_ip, dst_ip, src_tcp_port, dst_tcp_port)
        reverse_flow = (dst_ip, src_ip, dst_tcp_port, src_tcp_port)

        flow_chain_info = self.cluster_state.FLOW_TO_CHAIN_MAPPING.get(flow, None)

        # if current flow isnt in mapping, check reverse flow
        if flow_chain_info == None:
            flow_chain_info = self.cluster_state.FLOW_TO_CHAIN_MAPPING.get(reverse_flow, None)

        # if flow in both directions isn't in the mapping, create a new mapping
        if flow_chain_info == None:
            flow_chain_id, flow_chain = None, None
            # get corresponding chain for the flow
            for id, chain in self.cluster_state.CHAINS.items():
                if chain.SRC.get_ips()[0] == src_ip and chain.DST.get_ips()[0] == dst_ip:
                    flow_chain_id = id
                    flow_chain = chain
                    break
            
            if flow_chain == None:
                print(f"Unable to match a chain for flow: {src_ip} to {dst_ip}")
                return

            fw_index, nat_index = None, None

            for nf in flow_chain.NF_CHAIN:
                if nf == "fw":
                    fw_index = flow_chain.FW_INDEX % len(flow_chain.FW_POOL)
                    flow_chain.FW_INDEX += 1
                elif nf == "nat":
                    nat_index = flow_chain.NAT_INDEX % len(flow_chain.NAT_POOL)
                    flow_chain.NAT_INDEX += 1

            flow_chain_info = {
                "chain_id": flow_chain_id,
                "fw_index": fw_index,
                "nat_index": nat_index
            }

            # add the forward and reverse flow to mapping
            self.cluster_state.FLOW_TO_CHAIN_MAPPING[flow] = flow_chain_info
            self.cluster_state.FLOW_TO_CHAIN_MAPPING[reverse_flow] = flow_chain_info

            # if there is a NAT on the chain, add nat ip mapping as well
            if nat_index != None:
                nat_ips = flow_chain.NAT_POOL[nat_index].get_ips()
                nat_in_ip, nat_out_ip = nat_ips[0], nat_ips[1]

                nat_forward_flow = (nat_out_ip, dst_ip, src_tcp_port, dst_tcp_port)
                nat_reverse_flow = (nat_in_ip, src_ip, dst_tcp_port, src_tcp_port)

                self.cluster_state.FLOW_TO_CHAIN_MAPPING[nat_forward_flow] = flow_chain_info
                self.cluster_state.FLOW_TO_CHAIN_MAPPING[nat_reverse_flow] = flow_chain_info

        flow_chain = self.cluster_state.CHAINS[flow_chain_info["chain_id"]]

        # get the container objects for the path
        src_host = flow_chain.SRC
        dst_host = flow_chain.DST

        fw, nat = None, None

        if "fw" in flow_chain.NF_CHAIN:
            fw = flow_chain.FW_POOL[flow_chain_info["fw_index"]]

        if "nat" in flow_chain.NF_CHAIN:
            nat = flow_chain.NAT_POOL[flow_chain_info["nat_index"]]

        # if the switch that sent the packet in is ovs-br1
        if datapath.id == 1:
            # if there isn't a fw on the chain
            if fw == None:
                # if the packet came from the host, forward to switch 2 and the nat
                if in_port == src_host.OUT_PORT:
                    out_port = 1
                    new_dst_mac = nat.IN_MAC
                # if the packet came from switch 2, forward to the src host
                elif in_port == 1:
                    out_port = src_host.OUT_PORT
                    new_dst_mac = src_host.OUT_MAC
            # if there is a fw
            else:
                if in_port == src_host.OUT_PORT:
                    out_port = fw.IN_PORT
                    new_dst_mac = fw.IN_MAC
                elif in_port == fw.OUT_PORT:
                    out_port = 1
                    new_dst_mac = nat.IN_MAC
                elif in_port == fw.IN_PORT:
                    out_port = src_host.OUT_PORT
                    new_dst_mac = src_host.OUT_MAC
                elif in_port == 1:
                    out_port = fw.OUT_PORT
                    new_dst_mac = fw.OUT_MAC

        # if the switch that sent the packet in is ovs-br2
        else:
            # if the packet came from port1, forward to nat
            if in_port == 1:
                out_port = nat.IN_PORT
                new_dst_mac = nat.IN_MAC
            # if the packet came from the nat out_port, forward to dst
            elif in_port == nat.OUT_PORT:
                out_port = dst_host.IN_PORT
                new_dst_mac = dst_host.IN_MAC
            # if the packet came from the nat in_port, forward to switch 1
            elif in_port == nat.IN_PORT:
                out_port = 1
                # if there is a fw, set the new mac to the firewall else sent to the src host
                if fw == None:
                    new_dst_mac = src_host.OUT_MAC
                else:
                    new_dst_mac = fw.OUT_MAC
            else:
                out_port = nat.OUT_PORT
                new_dst_mac = nat.OUT_MAC
            
        match = parser.OFPMatch(
            in_port=in_port,
            eth_type=ether_frame.ethertype,
            eth_src=ether_frame.src,
            eth_dst=ether_frame.dst,
            ip_proto=6,
            ipv4_src=src_ip,
            ipv4_dst=dst_ip,
            tcp_src=src_tcp_port,
            tcp_dst=dst_tcp_port
        )
        
        actions = [parser.OFPActionSetField(eth_dst=new_dst_mac),
                   parser.OFPActionOutput(out_port, 0)]
        
        print("--------NEW FLOW--------")
        print(f"flow: {flow}, flow_chain: {flow_chain_info}" )
        print(f"dpid: {datapath.id}, in_port: {in_port}, out_port: {out_port}, new mac: {new_dst_mac}")
        print(src_host)
        print(dst_host)
        print(fw)
        print(nat)
        print()

        self.add_flow_init(datapath, 1, match, actions)

        out = msg.datapath.ofproto_parser.OFPPacketOut(
            datapath=msg.datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data)
        
        msg.datapath.send_msg(out)

    # NFV Manager
    def register_sfc_handler(self, new_entry):
        chain_id = str(new_entry["chain_id"])

        src, dst = None, None
        nat_launch_script, fw_launch_script = None, None

        # find the correspondint src and host object in the cluster state
        for s in self.cluster_state.SRC_POOL:
            if s.get_ips()[0] == new_entry["SRC"]["IP"]:
                src = s
                break

        for d in self.cluster_state.DST_POOL:
            if d.get_ips()[0] == new_entry["DST"]["IP"]:          
                dst = d
                break
        
        # get the nat and fw launch settings
        nat_settings = new_entry.get("nat", None)
        if nat_settings != None:
            nat_launch_script = nat_settings["init_script"]

        fw_settings = new_entry.get("fw", None)
        if fw_settings != None:
            fw_launch_script = fw_settings["init_script"]

        # create new chain and add the mapping to cluster state
        chain = nfv_util.CHAIN(
            new_entry["NF_CHAIN"],
            src,
            dst,
            fw_launch_script,
            nat_launch_script
            )
        
        self.cluster_state.CHAINS[chain_id] = chain

    def launch_handler(self, new_entry):
        chain_id = str(new_entry["chain_id"])
        # loop through the settings to create the specified NFs
        for key, value in new_entry.items():

            if key == "nat":
                self.launch_nat(chain_id, value)
            elif key == "fw":
                self.launch_fw(chain_id, value)

    
    def launch_nat(self, chain_id, settings):
        # create new name for the nat
        nat_name = f"nat{self.cluster_state.NAT_INDEX}"
        self.cluster_state.NAT_INDEX += 1
        
        # get specified launch script from registration
        launch_script = self.cluster_state.CHAINS[chain_id].NAT_LAUNCH_SCRIPT

        # get ip and mac from settings
        in_ip = settings[0]["ip"]["eth0"]
        out_ip = settings[0]["ip"]["eth1"]
        in_mac = settings[0]["mac"]["eth0"]
        out_mac = settings[0]["mac"]["eth1"]

        # launch the container
        cmd = f"echo $SUDO_PWD | sudo bash .{launch_script} {nat_name} {in_ip} {out_ip} {in_mac} {out_mac}"
        subprocess.run(cmd, shell=True)
        
        # create IP to MAC mapping for ARP
        self.IP_TO_MAC_MAPPING[in_ip] = in_mac
        self.IP_TO_MAC_MAPPING[out_ip] = out_mac
        
        # get respective port numbers
        in_port = self.cluster_state.SWITCH_2_PORT_INDEX
        out_port = self.cluster_state.SWITCH_2_PORT_INDEX + 1
        
        self.cluster_state.SWITCH_2_PORT_INDEX += 2

        # create and add the new NF container to the cluster state
        nat = nfv_util.NAT(nat_name, in_port, out_port, in_mac, out_mac, in_ip, out_ip)
        self.cluster_state.CHAINS[chain_id].NAT_POOL.append(nat)

    def launch_fw(self, chain_id, settings):
        # create new name for the fw
        fw_name = f"fw{self.cluster_state.FW_INDEX}"
        self.cluster_state.FW_INDEX += 1

        # get specified launch script from registration
        launch_script = self.cluster_state.CHAINS[chain_id].FW_LAUNCH_SCRIPT

        # get ip and mac from settings
        in_ip = settings[0]["args"][0]
        out_ip = settings[0]["args"][1]
        in_mac = settings[0]["mac"]["eth0"]
        out_mac = settings[0]["mac"]["eth1"]

        # launch the container
        cmd = f"echo $SUDO_PWD | sudo bash .{launch_script} {fw_name} {in_ip} {out_ip} {in_mac} {out_mac}"
        subprocess.run(cmd, shell=True)

        # get respective port numbers
        in_port = self.cluster_state.SWITCH_1_PORT_INDEX
        out_port = self.cluster_state.SWITCH_1_PORT_INDEX + 1
        
        self.cluster_state.SWITCH_1_PORT_INDEX += 2

        # create and add the new NF container to the cluster state
        fw = nfv_util.FW(fw_name, in_port, out_port, in_mac, out_mac)
        self.cluster_state.CHAINS[chain_id].FW_POOL.append(fw)

class ProjectRESTController(ControllerBase):  
    def __init__(self, req, link, data, **config):
        super(ProjectRESTController, self).__init__(req, link, data, **config)
        self.nfv_project_app = data["ProjectRESTController"]

    @route('nfv_project_app', "/register_sfc", methods=["PUT"])
    def register_sfc(self, req, **kwargs):       
        try:
            new_entry = req.json if req.body else {}
        except ValueError:
            return Response(status=400, content_type="text/plain", body="no sfc provided\n")
        
        self.nfv_project_app.register_sfc_handler(new_entry)

        return Response(content_type="text/plain", 
                        body=f"chain registered successfully\n")

    @route('nfv_project_app', "/launch_sfc", methods=["PUT"])
    def launch_sfc(self, req, **kwargs):
        try:
            new_entry = req.json if req.body else {}
        except ValueError:
            return Response(status=400, content_type="text/plain", body="no launch commands provided\n")
        
        self.nfv_project_app.launch_handler(new_entry)

        return Response(content_type="text/plain", 
                        body=f"NFs launched successfully\n")