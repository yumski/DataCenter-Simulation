# SDN Project: Software-Defined Networks

## Objectives

In this project, we will implement a set of OpenFlow rules that can adapt to network topologies changes and to traffic changes. To test the implementation, we will create a test serivce that will generate traffic between hosts in the network based on test config file.

## Prerequisities

* [Mininet](http://mininet.org/download/) >= 2.3.0
* [Ryu](https://ryu.readthedocs.io/en/latest/getting_started.html) >= 4.34
* [python](https://www.python.org/) >= 3.8
* [iperf](https://iperf.fr/iperf-download.php) >= 2.0.13
* [networkx](https://networkx.org/) >= 3.1
* [pyvis](https://pyvis.readthedocs.io/en/latest/) >= 0.3.2


## Project Structure

The project is organized as follows:

### project/
* [sdn_topo.py](project/sdn_topo.py) - Mininet topology file, create custom topology based on config file
* [sdn_controller.py](project/sdn_controller.py) - Ryu controller application, implement OpenFlow rules
* [sdn_utils.py](project/sdn_utils.py) - Utility functions for the controller application
* [sdn_test.py](project/sdn_test.py) - Test service, generate traffic between hosts in the network based on test config file
* [graph.html](project/graph.html) - Network graph visualization
* [main.py](project/main.py) - main entry for debug test
* [README.md](project/README.md) - Project README file

### project/config/
* [link_config.json](project/config/link_config.json) - Links configuration file, specify the links between switches and hosts, and their bandwidth and latency properties
* [params.json](project/config/params.json) - Ryu controller application parameters, specify the parameters for the controller application, such as S1, T1, T2, etc.
* [test1.json](project/config/test1.json) - Test service configuration file.
* [simple_loop.josn](project/config/simple_loop.json) - A simple loop topology.
* [complex_test.json](project/config/complex_tree.json) - A complex tree topology.

### params.json configuration options explained

The params.json file contains the following parameters:

* monitoring - [true|false], Enable or disable monitoring
* redistribute - [true|false], Enable or disable redistribution, only works with proactive path selection strategy
* path_selection_strategy - [shortest_path|widest_path|proactive_path], The path selection strategy
* S1 - [numbre], the size of the list of monitoring data structure
* T1 - [number], the time interval for monitoring
* T2 - [number], the time interval for redistribution

In order to verify the proactive path selection strategy with redistribution, you need to set below parameter combination:
    
```json
{
    "monitoring": true,
    "redistribute": true,
    "path_selection_strategy": "proactive_path",
    "S1": 5,
    "T1": 3,
    "T2": 20
}
```

## Installation

After installing the prerequisities, clone the repository.

```bash
git clone https://github.gatech.edu/bxu326/sdn_team_17_bxu_cfeng.git
```

## Running the project

Create the Mininet topology.

```bash
cd  sdn_team_17_bxu_cfeng/project
sudo mn --custom sdn_topo.py --topo topology --controller=remote --mac
```

Start the Ryu controller.

```bash
cd  sdn_team_17_bxu_cfeng/project
ryu-manager sdn_controller.py --observe-links
```

Once the topology is created and the controller is running, you can run mininet commands in the mininet CLI to test the network.

## Running the test service

The test service is a python script that will generate traffic between hosts in the network based on a test config file. The test service will create the topology automatically, so you will need to clean up the mininet topology started in previous step before running the test service.

```bash
sudo mn -c
```

To start the test service, run the following command in command window

```bash
sudo python sdn_test.py
```

The test service will prompt you to start Ryu controller application

```Console
Start RYU controller and continue. (Press Enter)
```

Start the Ryu controller application in another command window

```bash
cd  sdn_team_17_bxu_cfeng/project
ryu-manager sdn_controller.py --observe-links
```

Once the Ryu controller application is running, press enter in the test service command window, the test service will start the tests. An example output of test service looks like this:

```Console
Testing network connectivity
*** Ping: testing ping reachability
h1 -> h2 h3 h4 
h2 -> h1 h3 h4 
h3 -> h1 h2 h4 
h4 -> h1 h2 h3 
*** Results: 0% dropped (12/12 received)

Starting iperf test thread
Starting iperf test thread
Starting iperf test thread
Waiting for thread Process-1 to finish
Running iperf from h3 to h1 for 15 seconds with 100Mbits/sec bandwidth
Running iperf from h2 to h1 for 10 seconds with 100Mbits/sec bandwidth
Running iperf from h4 to h1 for 26 seconds with 100Mbits/sec bandwidth
Thread Process-1 finished
Waiting for thread Process-2 to finish
iperf from h2 to h1 finished
iperf from h3 to h1 finished
Thread Process-2 finished
Waiting for thread Process-3 to finish
iperf from h4 to h1 finished
Thread Process-3 finished
```


