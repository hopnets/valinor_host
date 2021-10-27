#!/bin/bash

PEER=root@hp043.utah.cloudlab.us
PEER_VALINOR_HOME=/users/erfanshz/valinor
LOCAL_INTERFACE_ID=3
PEER_INTERFACE_ID=3

rm -rf pings.csv no_valinor.csv valinor.csv summary.csv
sed -i '/#define FLOWINFO_MARKING_CTL 1/c\#define FLOWINFO_MARKING_CTL 0' inc/valinor.h
sed -i '/#define FLOWINFO_ORDERING_CTL 1/c\#define FLOWINFO_ORDERING_CTL 0' inc/valinor.h

ssh $PEER "sed -i '/#define FLOWINFO_MARKING_CTL 1/c\#define FLOWINFO_MARKING_CTL 0' ${PEER_VALINOR_HOME}/inc/valinor.h"
ssh $PEER "sed -i '/#define FLOWINFO_ORDERING_CTL 1/c\#define FLOWINFO_ORDERING_CTL 0' ${PEER_VALINOR_HOME}/inc/valinor.h"
ssh $PEER "pushd ${PEER_VALINOR_HOME} && make clean && make"
make clean && make
ssh $PEER 'killall mburst_marker'
ssh $PEER "nohup ${PEER_VALINOR_HOME}/build/valinor -- -p ${PEER_INTERFACE_ID} -c ${PEER_VALINOR_HOME}/server.json > foo.out 2> foo.err < /dev/null &"
sudo timeout -s INT 15 ./build/valinor -- -p $LOCAL_INTERFACE_ID -c client.json 
mv summary.csv no_valinor.csv
ssh $PEER 'killall valinor'
sed -i '/#define FLOWINFO_MARKING_CTL 0/c\#define FLOWINFO_MARKING_CTL 1' inc/valinor.h
sed -i '/#define FLOWINFO_ORDERING_CTL 0/c\#define FLOWINFO_ORDERING_CTL 1' inc/valinor.h
make clean && make
ssh $PEER 'killall valinor'
ssh $PEER "sed -i '/#define FLOWINFO_MARKING_CTL 0/c\#define FLOWINFO_MARKING_CTL 1' ${PEER_VALINOR_HOME}/inc/valinor.h"
ssh $PEER "sed -i '/#define FLOWINFO_ORDERING_CTL 0/c\#define FLOWINFO_ORDERING_CTL 1' ${PEER_VALINOR_HOME}/inc/valinor.h"
ssh $PEER "pushd ${PEER_VALINOR_HOME} && make clean && make"
ssh $PEER "nohup ${PEER_VALINOR_HOME}/build/valinor -- -p ${PEER_INTERFACE_ID} -c ${PEER_VALINOR_HOME}/server.json > foo.out 2> foo.err < /dev/null &"
sudo timeout -s INT 15 ./build/valinor -- -p $LOCAL_INTERFACE_ID -c client.json
mv summary.csv valinor.csv
echo "Experiment results for a single run:"
echo "#type	avg	std	min	5th	50th	90th	95th	99th	99.9th	99.99th"
echo "Network w/out Valinor marking and ordering:"
cat no_valinor.csv
echo ""
echo "Network with Valinor:"
cat valinor.csv
echo ""
ssh $PEER 'killall mburst_marker'
echo "Experiment Finished!"



