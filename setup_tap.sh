brctl addbr br0
ip tuntap add name tap7 mode tap
ip link set dev tap7 up
brctl addif br0 tap7
echo 'Interface tap7 created and added to bridge br0'
ip tuntap add name tap9 mode tap
ip link set dev tap9 up
brctl addif br0 tap9
echo 'Interface tap9 created and added to bridge br0'
