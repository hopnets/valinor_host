# Valinor host component implementation
## Targetting CoNEXT '21 Artifact Evaluation

To deploy and test host components, you need to bind your NIC to userspace drivers.
We used `ubuntu 18.04` featuring two `Intel Xeon E5-2640 v4 @ 2.40GHz` CPUs and two `Mellanox CX-4` network cards. 
We designate two server machines to serve as traffic sender and traffic receiver. In our Cloudlab setup, the first NIC is set up for external (SSH) communications and the second interface is used for benchmarking.

To set up the userspace drivers, on both servers, run:

    sudo apt update && sudo apt upgrade
    sudo apt install ninja-build python3-pip libnuma-dev
    pip3 install meson

Download Mellanox OFED drivers on both servers:

    cd ~
    wget https://www.mellanox.com/downloads/ofed/MLNX_OFED-5.4-1.0.3.0/MLNX_OFED_LINUX-5.4-1.0.3.0-ubuntu18.04-x86_64.tgz
    tar -xf MLNX_OFED_LINUX-5.4-1.0.3.0-ubuntu18.04-x86_64.tgz
    cd MLNX_OFED_LINUX-5.4-1.0.3.0-ubuntu18.04-x86_64/
    sudo ./mlnxofedinstall --upstream-libs --dpdk
    sudo /etc/init.d/openibd restart

reply `y` to the prompt to install the required dependencies and Mellanox OFED.
Note1: Skip this step if you are using an Intel NIC.

Install DPDK on both servers:

    cd ~
    wget https://fast.dpdk.org/rel/dpdk-19.11.10.tar.xz
    tar xf dpdk-19.11.10.tar.xz
    cd dpdk-stable-19.11.10/
    sudo mkdir /mnt/huge
    sudo mount -t hugetlbfs pagesize=1GB /mnt/huge

Note2: On inter NICs, you must manually modprobe the userspace driver and bind your network interface to it. The instructions for doing so can be found at https://doc.dpdk.org/guides/linux_gsg/linux_drivers.html. Feel free to reach us, in case you have issues setting up your NIC.

To allocate hugepages, using root user, on a non-NUMA server run:

    echo 4096 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

To allocate hugepages, using root user, on a NUMA server run:

    echo 4096 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
    echo 4096 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages

Check if meson is found in your path. If not, try to open a new bash session.
Continue with installing DPDK libs:

    meson build
    cd build
    ninja
    sudo ninja install
    sudo ldconfig

Clone the Valinor repository:

    cd ~
    git clone https://github.com/hopnets/valinor_host

On the receiver machine, switch to the client app:

    git checkout receiver

On both servers run:

    cd valinor
    make

Finally, you should enable root SSH access from the sender machine to the receiver. To do that, first run `ssh-keygen` command on the sender machine. Then copy the contents of `~/.ssh/id_rsa.pub` on the sender machine to `/root/.ssh/authorized_keys` on the receiver machine. Run `ssh root@<RECEIVER_PUBLIC_IP>` to make sure you have proper SSH access before continuing.

On the sender machine, open `run.sh` script.
You must modify four variables on the top to match you environment:

    PEER=root@<RECEIVER_PUBLIC_IP>
    PEER_VALINOR_HOME=<PATH_TO_VALINOR_HOME_ON_RECEIVER>
    LOCAL_INTERFACE_ID=<DPDK_INTERFACE_ID_ON_SENDER>
    PEER_INTERFACE_ID=<DPDK_INTERFACE_ID_ON_RECEIVER>
    
On sender machine, open `client.json`. You must update the three MAC addresses provided in the JSON file to match your testbed.
On the receiver machine, open `server.json`. Repeat the above procedure to have a correct ARP table.

Run the script on the sender machine to perform the latency experiment:

    sudo ./run.sh


Example output of the script:

    Experiment results for a single run:
    #type avg std min 5th 50th 90th 95th 99th 99.9th 99.99th
    
    Network w/out Valinor marking and ordering:
    All 10131 0 9131 9667 9842 10105 10353 18106 26505 209635        
    Network with Valinor:
    All 10481 0  9520 10001 10189 10461 10787 18626 27419 225107        
    Experiment Finished!
    
    
 ### Authors for further contact:
- Erfan Sharafzadeh (erfan@cs.jhu.edu)
- Sepehr Abdous (sabdous1@jhu.edu)
    
 ### Open source code used in this repository:
- Shenango (https://github.com/shenango/shenango)
- Frozen (https://github.com/cesanta/frozen)
- log.c (https://github.com/rxi/log.c)
