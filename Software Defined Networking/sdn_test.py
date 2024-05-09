from mininet.cli import CLI
from mininet.link import TCLink
from mininet.net import Mininet
from mininet.node import RemoteController
from sdn_topo import SimpleTopo
import sdn_utils as utils
from multiprocessing import Process
import time

class TestService(object):
    def __init__(self):
        self.testconfig = {}

    def run_test(self):
        self.testconfig = utils.load_json_config("./config/test1.json")

        topo = SimpleTopo()
        net = Mininet(topo=topo, link=TCLink, controller=None, autoSetMacs=True)

        print("Start RYU controller and continue. (Press Enter)")
        input()

        net.addController(
            "rmController", controller=RemoteController, ip="127.0.0.1", port=6633
        )
        net.start()

        print("Testing network connectivity")
        net.pingAll()
        print()

        # start iperf tests
        threads = []
        t0 = time.time()
        for test in self.testconfig:
            client, server = net.get(test["client"]), net.get(test["server"])

            # start iperf server
            server.cmd(f"iperf -s -p 5001 &")

            # start iperf client
            print(f"Starting iperf test thread")
            t = Process(
                target=self.run_iperf,
                args=(test, client, server, t0),
            )
            threads.append(t)
            t.start()

        # wait for all threads to finish
        for t in threads:
            print(f"Waiting for thread {t.name} to finish")
            t.join(timeout=10)
            print(f"Thread {t.name} finished")

        # delete all threads
        del threads[:]

        print()

        CLI(net)
        net.stop()

    # thread function to run iperf test
    def run_iperf(self, test, client, server, t0):

        # sleep until test begin time is reached
        if time.time() - t0 < int(test["test"][0]["begin"]):
            time.sleep(int(test["test"][0]["begin"]) - (time.time() - t0))

        # start each test step
        for step in test["test"]:
            seconds = int(step["end"]) - int(step["begin"])
            bandwidth = step["bandwidth"]
            print(
                f"Running iperf from {client} to {server} for {seconds} seconds with {bandwidth}bits/sec bandwidth"
            )
            result = client.cmd(f"iperf -c {server.IP()} -p 5001 -u -b {bandwidth} -t {seconds}")
            # print(result)
        print(f"iperf from {client} to {server} finished")


if __name__ == "__main__":
    TestService().run_test()
