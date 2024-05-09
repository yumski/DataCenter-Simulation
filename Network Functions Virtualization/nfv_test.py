import subprocess
import json
import time
import sys
from multiprocessing import Process


class TestService(object):
    def __init__(self):
        self.testconfig = {}

    # load json config file
    def load_json_config(self, filename):
        with open(filename, "r") as f:
            config_options = json.load(f)
        return config_options

    def run_test(self):
        # get profile name from command line
        if len(sys.argv) != 3:
            print("Usage: python nfv_test.py <profile_name> <server port number>")
            sys.exit(1)

        profile_name = sys.argv[1]
        server_port = sys.argv[2]

        self.testconfig = self.load_json_config(profile_name)

        # start iperf tests
        threads = []
        t0 = time.time()
        port_inc = 0
        for test in self.testconfig["profiles"]:
            client = test["src_container"]
            server = test["dst_container"]
            server_ip = test["dst_ip"]
            server_port = int(server_port) + port_inc
            flows = test["flows"]

            # start iperf server
            cmd = f"docker exec {server} iperf3 -s -p {server_port} -D &"
            subprocess.run(cmd, shell=True)

            # start iperf client
            print(f"Starting iperf test thread")
            t = Process(
                target=self.run_iperf,
                args=(flows, client, server, server_ip, server_port, t0),
            )
            threads.append(t)
            t.start()

            port_inc += 1

        # wait for all threads to finish
        for t in threads:
            print(f"Waiting for thread {t.name} to finish")
            t.join(timeout=10)
            print(f"Thread {t.name} finished")

        # delete all threads
        del threads[:]

        print("All iperf tests finished")

    # thread function to run iperf test
    def run_iperf(self, flows, client, server, server_ip, server_port, t0):

        # sleep until test begin time is reached
        if time.time() - t0 < int(flows[0]["start_time"]):
            time.sleep(int(flows[0]["start_time"]) - (time.time() - t0))

        # start each test step
        for flow in flows:
            seconds = int(flow["end_time"]) - int(flow["start_time"])
            num_flows = int(flow["num_flows"])
            print(
                f"Running iperf from {client} to {server} with {num_flows} flows for {seconds} seconds"
            )
            cmd = f"docker exec {client} iperf3 -c {server_ip} -p {server_port} -P {num_flows} -t {seconds}"
            print(cmd)
            subprocess.run(cmd, shell=True)
            # print(result)
        print(f"iperf from {client} to {server} finished")


if __name__ == "__main__":
    TestService().run_test()