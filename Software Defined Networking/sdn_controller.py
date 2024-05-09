from collections import deque
from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp, ipv4, ipv6
import ryu.topology.event as event
from ryu.topology.api import get_switch, get_link
from ryu.lib import hub
import networkx as nx
import sdn_utils as utils
import logging
import multiprocessing

DEFAULT_LATENCY = 2
DEFAULT_BANDWIDTH = 100


class ProjectSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectSwitch, self).__init__(*args, **kwargs)

        self.logger.setLevel(logging.INFO)

        # initialize mac address table.
        self.mac_to_port = {}

        # initialize datapaths
        self.datapaths = {}

        # ryu config options
        self.params = utils.load_json_config("./config/params.json")

        # link config options
        self.link_config = utils.load_json_config("./config/link_config.json")

        # path selection strategy
        self.path_selection_strategy = self.params["path_selection_strategy"]

        # size of bandwidth list
        self.S1 = self.params["S1"]

        # monitor interval
        self.T1 = self.params["T1"]

        # redistribute interval
        self.T2 = self.params["T2"]

        # data flow statistic list
        self.flow_stats = {}

        # port statistic list
        self.port_stats = {}

        # bytes sent between two hosts
        self.comm_list = {}

        # rules to be installed
        self.comm_rules = []

        # network graph
        self.graph = nx.DiGraph()

        # lock object
        self.lock = multiprocessing.Lock()

        # start monitoring thread
        if self.params["monitoring"]:
            self.monitor_thread = hub.spawn(self._monitor)

        # redistributing flag
        self.redistributing = False

        # redistribute thread
        if (
            self.params["path_selection_strategy"] == "proactive_path"
            and self.params["redistribute"]
        ):
            self.redistribute_thread = hub.spawn(self._redistribute)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Called every time, when the controller receives a PACKET_IN message
        :type ev: ryu.controller.ofp_event.EventOFPPacketIn
        :return: None
        :rtype: None
        """

        # if redistribution is in progress, return
        with self.lock:
            if self.redistributing:
                return

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        dpid = datapath.id
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        # create a Packet object out of the payload
        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        ip_pkt_6 = pkt.get_protocol(ipv6.ipv6)
        arp_pkt = pkt.get_protocol(arp.arp)

        # Don't do anything with IPV6 packets.
        if isinstance(ip_pkt_6, ipv6.ipv6):
            actions = []
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6)
            self.add_flow(datapath, 1, match, actions)
            return

        # ARP Protcol
        if isinstance(arp_pkt, arp.arp):
            if self.mac_learning(dpid, eth.src, in_port) is False:
                self.logger.debug("ARP packet enter in different ports")
                return
            # Complete ARP protocol
            self.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip, eth)

        # This is the focus of this workshop -> Process the IPv4 message
        if isinstance(ip_pkt, ipv4.ipv4):
            # self.lock.acquire()
            # try:
            # find the switch in the mac_to_port table
            mac_to_port_table = self.mac_to_port.get(dpid)
            if mac_to_port_table is None:
                self.logger.info("Dpid is not in mac_to_port")
                return
            # source and destination mac address of the ethernet packet
            dst = eth.dst
            src = eth.src

            out_port = None
            path = []
            # "Known destination MAC address" -> We have seen this before
            if dst in self.graph:
                if self.path_selection_strategy == "shortest_path":
                    # shortest path strategy
                    path = nx.shortest_path(self.graph, src, dst, weight="latency")
                    print(f"shortest path: {path}")
                    next = path[path.index(dpid) + 1]
                    out_port = self.graph[dpid][next]["port"]
                elif self.path_selection_strategy == "widest_path":
                    # widest path strategy
                    path, minBandwidth = utils.widest_path(
                        self.graph, src, dst, weight="bandwidth"
                    )
                    print(f"widest path: {path} with Bandwidth: {minBandwidth:.2f}Mbps")
                    next = path[path.index(dpid) + 1]
                    out_port = self.graph[dpid][next]["port"]
                elif self.path_selection_strategy == "proactive_path":
                    # proactive path strategy
                    path, minBandwidth = utils.widest_path(
                        self.graph, src, dst, weight="free_bandwidth"
                    )
                    if minBandwidth == float("inf") or path is None:
                        print("fall back to static widest path strategy")
                        path, minBandwidth = utils.widest_path(
                            self.graph, src, dst, weight="bandwidth"
                        )
                        print(
                            f"widest path: {path} with Bandwidth: {minBandwidth:.2f}Mbps"
                        )
                    else:
                        print(
                            f"proactive path: {path} with Bandwidth: {minBandwidth:.2f}Mbps"
                        )
                    try:
                        next = path[path.index(dpid) + 1]
                        out_port = self.graph[dpid][next]["port"]
                    except:
                        self.logger.info(f" path = {path}, dpid = {dpid}")
                        return

                else:
                    # Normal static flows
                    out_port = mac_to_port_table[dst]

                actions = [parser.OFPActionOutput(out_port)]

                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_src=src,
                    eth_dst=dst,
                    eth_type=eth.ethertype,
                )

                # Add the flow to the switch
                self.add_flow(datapath, 1, match, actions)

                print(f"packet in s{dpid} src={src} dst={dst} in_port={in_port}")

                # Send packet to its destination
                self.send_packet_out(
                    datapath, msg.buffer_id, in_port, out_port, msg.data
                )

                utils.draw_graph(self.graph)

            # "Unknown destination MAC address"
            else:
                # MAC is not Known
                if self.mac_learning(dpid, src, in_port) is False:
                    print(f"packet in s{dpid} src={src} dst={dst} in_port={in_port}")
                    self.logger.debug("IPV4 packet enter in different ports")
                    return
                else:
                    print(f"packet in s{dpid} src={src} dst={dst} in_port={in_port}")
                    # we don't know anything, so flood the network
                    self.flood(msg)
        # finally:
        #     self.lock.release()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install the table-miss flow entry.
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match, instructions=inst
        )
        datapath.send_msg(mod)

    def delete_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if datapath.id in self.mac_to_port:
            for dst in self.mac_to_port[datapath.id].keys():
                match = parser.OFPMatch(eth_dst=dst)
                mod = parser.OFPFlowMod(
                    datapath,
                    command=ofproto.OFPFC_DELETE,
                    out_port=ofproto.OFPP_ANY,
                    out_group=ofproto.OFPG_ANY,
                    priority=1,
                    match=match,
                )
                datapath.send_msg(mod)

    def arp_forwarding(self, msg, src_ip, dst_ip, eth_pkt):
        """
        This forwards the ARP message, to obtain the MAC address, depending if it is now different acctions are taken.
        :type msg: ryu.ofproto.ofproto_v1_3_parser.OFPPacketIn - An object which describes the corresponding OpenFlow message.
        :type src_ip: string
        :type dst_ip: string
        :type eth_pkt: ryu.lib.packet.ethernet
        :return: None
        :rtype: None
        """
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        out_port = self.mac_to_port[datapath.id].get(eth_pkt.dst)

        # What is the difference if we know the mac address and if we don't
        if out_port is not None:
            match = parser.OFPMatch(
                in_port=in_port,
                eth_src=eth_pkt.src,
                eth_dst=eth_pkt.dst,
                eth_type=eth_pkt.ethertype,
            )
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)
            self.send_packet_out(datapath, msg.buffer_id, in_port, out_port, msg.data)
            self.logger.debug("Reply ARP to knew host")
        else:
            self.flood(msg)

    def _build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
        This function creates the packet that is going to be sent to the switch
        :type datapath: ryu.controller.controller.Datapath
        :type buffer_id: integer - ID assigned by datapath
        :type src_port: integer - source port
        :type dst_port: integer- output port
        :type data: Packet data of a binary type value or an instances of packet.Packet.
        :return: packet to be sent
        :rtype: OFPPacketOut
        """
        actions = []
        if dst_port:
            actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port))

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=buffer_id,
            data=msg_data,
            in_port=src_port,
            actions=actions,
        )
        return out

    def send_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
        This function sents the packet to the corresponding switch
        :type datapath: ryu.controller.controller.Datapath
        :type buffer_id: integer - ID assigned by datapath
        :type src_port: integer - source port
        :type dst_port: integer- output port
        :type data: Packet data of a binary type value or an instances of packet.Packet.
        :return: packet to be sent
        :rtype: OFPPacketOut
        """
        out = self._build_packet_out(datapath, buffer_id, src_port, dst_port, data)
        if out:
            datapath.send_msg(out)

    def flood(self, msg):
        """
        This function sents a message to flood the network to obtain ------------. What are we obtaining here?
        :type msg: ryu.ofproto.ofproto_v1_3_parser.OFPPacketIn - An object which describes the corresponding OpenFlow message.
        :return: None
        :rtype: None
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        out = self._build_packet_out(
            datapath,
            ofproto.OFP_NO_BUFFER,
            ofproto.OFPP_CONTROLLER,
            ofproto.OFPP_FLOOD,
            msg.data,
        )
        datapath.send_msg(out)

    def mac_learning(self, dpid, src_mac, in_port):
        """
        If an unknown mac address is found, learn that for future packages
        :type dpip: string - name for the switch (datapath)
        :type src_mac: string
        :type in_port: int
        :return: if it was correctly learned
        :rtype: Bool
        """
        # Initialize value on the dictionary
        self.mac_to_port.setdefault(dpid, {})
        # If the mac is already known
        if src_mac in self.mac_to_port[dpid]:
            # If the mac is comming from a different port that it was initiallly known
            if in_port != self.mac_to_port[dpid][src_mac]:
                return False
        else:
            # Store port used for the given MAC address.
            self.mac_to_port[dpid][src_mac] = in_port

            # learn host mac address and add it to the graph
            if src_mac not in self.graph:
                self.graph.add_node(src_mac)

                last_switch = None
                # add edge from switch to host
                self.graph.add_edge(
                    dpid,
                    src_mac,
                    port=in_port,
                    bandwidth=DEFAULT_BANDWIDTH,
                    free_bandwidth=DEFAULT_BANDWIDTH,
                    latency=DEFAULT_LATENCY,
                    label=f"{DEFAULT_LATENCY}ms\n{DEFAULT_BANDWIDTH}Mbps"
                )

                # add edge from host to switch
                self.graph.add_edge(
                    src_mac,
                    dpid,
                    port=0,
                    bandwidth=DEFAULT_BANDWIDTH,
                    free_bandwidth=DEFAULT_BANDWIDTH,
                    latency=DEFAULT_LATENCY,
                    label=f"{DEFAULT_LATENCY}ms\n{DEFAULT_BANDWIDTH}Mbps"
                )

                # draw graph
                utils.draw_graph(self.graph)

            return True

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug("register datapath: %016x", datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug("unregister datapath: %016x", datapath.id)
                del self.datapaths[datapath.id]

    # mointoring thread method
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.T1)

    # redistribute thread method
    def _redistribute(self):
        while True:
            hub.sleep(self.T2)
            self.redistribute()

    def _request_stats(self, datapath):
        self.logger.debug("send stats request: %016x", datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    def flow_filter(self, flow):
        return flow.priority == 1 and all(
            x in flow.match for x in ["in_port", "eth_src", "eth_dst", "eth_type"]
        )

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        self.flow_stats.setdefault(dpid, {})

        self.logger.info("===> flow statistics")
        self.logger.info(
            "datapath         "
            "in-port  eth-src           eth-dst           eth-type  "
            "out-port packets  bytes    timeout  duration usage(Mbps)"
        )
        self.logger.info(
            "---------------- "
            "-------- ----------------- ----------------- --------  "
            "-------- -------  -------- -------- -------- -----------"
        )

        for stat in sorted(
            [flow for flow in body if self.flow_filter(flow)],
            key=lambda flow: (flow.match["in_port"], flow.match["eth_dst"]),
        ):
            eth_src = stat.match["eth_src"]
            eth_dst = stat.match["eth_dst"]
            in_port = stat.match["in_port"]
            out_port = stat.instructions[0].actions[0].port
            eth_type = stat.match["eth_type"]
            duration = stat.duration_sec + stat.duration_nsec / 1e9

            # key to identify a flow
            key = (eth_src, eth_dst, in_port, out_port, eth_type)

            # flow statistics as queue of size S1
            value = deque(maxlen=self.S1)

            # save flow statistics
            self.flow_stats[dpid].setdefault(key, value)

            # calculate current bandwidth usage
            last_bytes, last_packets = 0, 0
            cur_bytes, cur_packets = stat.byte_count, stat.packet_count
            if len(self.flow_stats[dpid][key]) > 0:
                last_bytes = self.flow_stats[dpid][key][-1]["last_bytes"]
                cur_bytes = stat.byte_count - last_bytes

                last_packets = self.flow_stats[dpid][key][-1]["last_packets"]
                cur_packets = stat.packet_count - last_packets

            # calculate average bandwidth usage in time interval T1
            avg_Mbps = 0
            if len(self.flow_stats[dpid][key]) > 0:
                avg_Mbps = utils.bps_to_mbps(
                    max(
                        sum(item["cur_bytes"] for item in self.flow_stats[dpid][key]), 0
                    )
                    / len(self.flow_stats[dpid][key])
                    / self.T1
                )

            self.flow_stats[dpid][key].append(
                {
                    "last_bytes": stat.byte_count,
                    "cur_bytes": cur_bytes,
                    "last_packets": stat.packet_count,
                    "cur_packets": cur_packets,
                    "duration": duration,
                    "avg_Mbps": avg_Mbps,
                }
            )

            # set free bandwidth information to the link
            if self.graph.has_edge(dpid, eth_dst):
                self.graph[dpid][eth_dst]["free_bandwidth"] = (
                    self.graph[dpid][eth_dst]["bandwidth"] - avg_Mbps
                )

            if self.graph.has_edge(eth_dst, dpid):
                self.graph[eth_dst][dpid]["free_bandwidth"] = (
                    self.graph[eth_dst][dpid]["bandwidth"] - avg_Mbps
                )

            # collect comm_list information
            with self.lock:
                self._collect_comm_list_info(self.flow_stats)

            # print flow statistics
            self.logger.info(
                "%016x %8x %17s %17s %8s %8d %8d %9d %8d %8d %10.2f",
                dpid,
                in_port,
                eth_src,
                eth_dst,
                utils.get_ethertype(eth_type),
                out_port,
                stat.packet_count,
                stat.byte_count,
                stat.hard_timeout,
                duration,
                avg_Mbps,
            )

    # collect comm_list information
    def _collect_comm_list_info(self, stat):
        for dpid in stat:
            for stat_key in stat[dpid]:

                key = (stat_key[0], stat_key[1])
                value = deque(maxlen=self.S1)

                # comm_list initialization
                self.comm_list.setdefault(key, value)

                self.comm_list[key] = stat[dpid][stat_key]

    # calculate and apply redistruibute flow rules
    def redistribute(self):

        # create default topology graph
        graph = utils.create_default_graph(self.graph)

        # remove flow rules
        self.comm_rules = []

        # calculate the max bandwidth usage of two hosts
        comm_usage_list = {}
        for eth_src, eth_dst in self.comm_list:
            if (eth_dst, eth_src) in self.comm_list:
                max_usage = max(
                    self.comm_list[(eth_src, eth_dst)][-1]["avg_Mbps"],
                    self.comm_list[(eth_dst, eth_src)][-1]["avg_Mbps"],
                )
                comm_usage_list[(eth_dst, eth_src)] = max_usage
            else:
                comm_usage_list[(eth_src, eth_dst)] = self.comm_list[
                    (eth_src, eth_dst)
                ][-1]["avg_Mbps"]

        # sort comm_list by average packets per second
        sorted_comm_list = dict(
            sorted(comm_usage_list.items(), key=lambda x: x[1], reverse=True)
        )

        
        # print sorted comm_list
        self.logger.debug("===> sorted comm_list")
        self.logger.debug(sorted_comm_list)

        hostspairs = []
        for eth_src, eth_dst in sorted_comm_list:
            if (eth_dst, eth_src) in hostspairs or (eth_src, eth_dst) in hostspairs:
                continue
            hostspairs.append((eth_src, eth_dst))
        
        # print hostspairs
        self.logger.debug("===> hostspairs")
        self.logger.debug(hostspairs)

        # calculate redistruibute flow rules
        for eth_src, eth_dst in hostspairs:
            # get the latest average bytes per second
            avg_Mbps = sorted_comm_list[(eth_src, eth_dst)]
                
            # find the widest path for the given eth_src and eth_dst
            path, minBandwidth = utils.widest_path(
                graph, eth_src, eth_dst, weight="free_bandwidth"
            )

            # print calculated path and bandwidth
            self.logger.debug(
                f"widest path: {path} with Bandwidth: {minBandwidth:.2f}Mbps"
            )

            if len(path) > 0 and minBandwidth > 0:
                # get the switches on the path
                # switches = path[1:-1]

                # add flow rules for the given src and dst on path
                self.comm_rules.extend(self.get_flow_rules(path, eth_src, eth_dst))

                self.logger.debug("extend new path")
                self.logger.debug(self.comm_rules)

            else:
                self.logger.info(
                    f"no path between {eth_src} and {eth_dst}, fall back to static widest path strategy"
                )

                # fall back to static widest path strategy
                path, minBandwidth = utils.widest_path(
                    graph, eth_src, eth_dst, weight="bandwidth"
                )
                # add flow rules for the given src and dst on path
                self.comm_rules.extend(self.get_flow_rules(path, eth_src, eth_dst))

            # update the free bandwidth of the links in the path
            for i in range(len(path) - 2):
                src, dst = path[i], path[i + 1]
                graph[src][dst]["free_bandwidth"] = max(
                    graph[src][dst]["free_bandwidth"] - avg_Mbps, 0
                )
                graph[dst][src]["free_bandwidth"] = max(
                    graph[dst][src]["free_bandwidth"] - avg_Mbps, 0
                )

            # print free bandwidth of the links in the graph
            self.logger.debug("===> free bandwidth")
            for src, dst in graph.edges():
                self.logger.debug(
                    f"({src}, {dst}): {graph[src][dst]['free_bandwidth']:.2f}Mbps"
                )
            

        if self.comm_rules:
            self.logger.info("===> redistruibute flow rules")
            self.logger.debug(self.comm_rules)

            with self.lock:
                # set redistributing flag
                self.redistributing = True

                # delete all flow rules
                for dpid in self.datapaths:
                    self.delete_flow(self.datapaths[dpid])

                # clean comm_list
                self.comm_list = {}

                # install redistruibute flow rules
                for rule in self.comm_rules:
                    self.logger.info(f"install flow rule: {rule}")
                    datapath = self.datapaths[rule["dpid"]]
                    parser = datapath.ofproto_parser
                    actions = [parser.OFPActionOutput(rule["out_port"])]
                    match = parser.OFPMatch(
                        in_port=rule["in_port"],
                        eth_src=rule["eth_src"],
                        eth_dst=rule["eth_dst"],
                        eth_type=ether_types.ETH_TYPE_IP,
                    )
                    self.add_flow(datapath, 1, match, actions)

                # draw graph with free bandwidth information
                # for src, dst in graph.edges():
                #     graph[src][dst]["label"] = f"{graph[src][dst]['latency']}ms\n{graph[src][dst]['free_bandwidth']:.2f}Mbps"
                # utils.draw_graph(graph)

                # reset redistributing flag
                self.redistributing = False

                self.logger.info("redistruibution completed")


    # get flow rules for the given src and dst on path
    def get_flow_rules(self, path, eth_src, eth_dst):
        rules = []

        # add flow rule from switch to switch
        for i in range(1, len(path) - 1):
            dpid = path[i]
            in_port = self.mac_to_port[dpid].get(eth_src)
            out_port = self.mac_to_port[dpid].get(eth_dst)

            # out_port is not found in mact_to_port table
            # search the out_port from the graph
            if out_port is None:
                edge_data = self.graph.get_edge_data(path[path.index(dpid) + 1], path[path.index(dpid)])
                if edge_data:
                    out_port = edge_data["port"]

            # in_port is not found in mact_to_port table
            # search the in_port from the graph
            if in_port is None:
                edge_data = self.graph.get_edge_data(path[dpid], path[path.index(dpid) - 1])
                if edge_data:
                    in_port = edge_data["port"]

            rules.append(
                {
                    "dpid": dpid,
                    "eth_src": eth_src,
                    "eth_dst": eth_dst,
                    "in_port": in_port,
                    "out_port": out_port,
                }
            )

        # print get flow rules
        self.logger.debug("===> get flow rules")
        for rule in rules:
            self.logger.debug(f"flow rule: {rule}")

        return rules

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        self.port_stats.setdefault(dpid, {})

        self.logger.info("===> port statistics")
        self.logger.info(
            "datapath         port     "
            "rx-pkts  rx-bytes rx-error rx-drop  "
            "tx-pkts  tx-bytes tx-error tx-drop  usage(Mbps)"
        )
        self.logger.info(
            "---------------- -------- "
            "-------- -------- -------- -------- "
            "-------- -------- -------- -------- -----------"
        )

        for stat in sorted(body, key=attrgetter("port_no")):
            # ignore Local openflow "port"
            if stat.port_no == ofproto_v1_3.OFPP_LOCAL:
                continue

            key = stat.port_no
            value = deque(maxlen=self.S1)

            # save port statistics
            self.port_stats[dpid].setdefault(key, value)

            # calculate current bandwidth usage
            last_bytes = 0
            cur_bytes = stat.rx_bytes + stat.tx_bytes
            if len(self.port_stats[dpid][key]) > 0:
                last_bytes = self.port_stats[dpid][key][-1]["last_bytes"]
                cur_bytes = stat.rx_bytes + stat.tx_bytes - last_bytes

            # calculate average bandwidth usage in time interval T1
            avg_Mbps = 0
            if len(self.port_stats[dpid][key]) > 0:
                avg_Mbps = utils.bps_to_mbps(
                    max(
                        sum(item["cur_bytes"] for item in self.port_stats[dpid][key]), 0
                    )
                    / len(self.port_stats[dpid][key])
                    / self.T1
                )

            self.port_stats[dpid][key].append(
                {
                    "last_bytes": stat.rx_bytes + stat.tx_bytes,
                    "cur_bytes": cur_bytes,
                    "avg_Mbps": avg_Mbps,
                }
            )

            # print port statistics
            self.logger.info(
                "%016x %8x %8d %8d %8d %8d %8d %8d %8d %8d   %8.2f",
                ev.msg.datapath.id,
                stat.port_no,
                stat.rx_packets,
                stat.rx_bytes,
                stat.rx_errors,
                stat.rx_dropped,
                stat.tx_packets,
                stat.tx_bytes,
                stat.tx_errors,
                stat.tx_dropped,
                avg_Mbps,
            )

        # set free bandwidth information to the link
        self.logger.debug("===> set link free bandwidth")
        self.logger.debug(self.port_stats)
        self.set_link_freebandwidth()

    def set_link_freebandwidth(self):
        for edge in self.graph.edges():
            src, dst = edge[0], edge[1]

            # calculate link freebandwidth only when both ports are monitored
            if src in self.port_stats and dst in self.port_stats:
                src_port = self.graph[src][dst]["port"]
                dst_port = self.graph[dst][src]["port"]

                src_port_stats = self.port_stats[src][src_port][-1]
                dst_port_stats = self.port_stats[dst][dst_port][-1]

                link_usage = max(src_port_stats["avg_Mbps"], dst_port_stats["avg_Mbps"])
                free_bandwidth = max(self.graph[src][dst]["bandwidth"] - link_usage, 0)
                self.graph[src][dst]["free_bandwidth"] = free_bandwidth
                self.graph[dst][src]["free_bandwidth"] = free_bandwidth

    @set_ev_cls(event.EventSwitchEnter)
    def _event_switch_enter_handler(self, ev):
        self.logger.info("Switch entered: %s", ev.switch.dp.id)
        self.graph.add_node(ev.switch.dp.id)
        # draw graph
        utils.draw_graph(self.graph)

    @set_ev_cls(event.EventSwitchLeave)
    def _event_switch_leave_handler(self, ev):
        self.logger.info("Switch left: %s", ev.switch.dp.id)
        self.graph.remove_node(ev.switch.dp.id)
        # draw graph
        utils.draw_graph(self.graph)

    @set_ev_cls(event.EventLinkAdd)
    def _event_link_add_handler(self, ev):
        self.logger.info("Link added: %s", ev.link)

        bandwidth = DEFAULT_BANDWIDTH
        latency = DEFAULT_LATENCY

        # get bandwith and latency from topo config
        input_port = f"s{ev.link.src.dpid}-{ev.link.src.port_no}"
        output_port = f"s{ev.link.dst.dpid}-{ev.link.dst.port_no}"
        for link in self.link_config["links"]:
            if (
                link["input_port"] == input_port and link["output_port"] == output_port
            ) or (
                link["input_port"] == output_port and link["output_port"] == input_port
            ):
                bandwidth = link["bandwidth"]
                latency = link["latency"]
                break

        self.graph.add_edge(
            ev.link.src.dpid,
            ev.link.dst.dpid,
            port=ev.link.src.port_no,
            bandwidth=bandwidth,  # bandwidth of the link, read from topo config
            free_bandwidth=bandwidth,  # free bandwidth, calculated by monitoring thread
            latency=latency,  # latency of the link, read from topo config
            label=f"{latency}ms\n{bandwidth}Mbps"
        )

        # draw graph
        utils.draw_graph(self.graph)

    @set_ev_cls(event.EventLinkDelete)
    def _event_link_delete_handler(self, ev):
        self.logger.info("Link deleted: %s", ev.link)
        if self.graph.has_edge(ev.link.src.dpid, ev.link.dst.dpid):
            self.graph.remove_edge(ev.link.src.dpid, ev.link.dst.dpid)

            # reset network flow table
            for dpid in self.datapaths:
                self.delete_flow(self.datapaths[dpid])

            # reset mac to port table
            for dpid in self.mac_to_port:
                self.mac_to_port[dpid] = {}

        # draw graph
        utils.draw_graph(self.graph)
